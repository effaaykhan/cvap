package scanpoint

import (
	"regexp"
	"strings"
	"testing"

	"github.com/effaaykhan/cvap/internal/enginewire"
)

// TestBuiltinBannerMatchesClassifyRealBanners asserts the built-in banner set
// resolves real, safe-mode-reachable greetings to the right service — the B22
// gap session 24 measured, where VNC's RFB greeting arrived and nothing matched
// it. The cases that already passed (SSH, FTP) are regressions kept here so a
// change that fixes VNC cannot quietly break them.
//
// The matcher mirrors internal/engines/fingerprint.evaluate: port-scoped,
// first-hit-wins, lifting the version/product/info capture groups. It is a few
// lines rather than an import because enginewire.Match is the contract and the
// engine is not on this package's import allowlist.
func TestBuiltinBannerMatchesClassifyRealBanners(t *testing.T) {
	type want struct {
		service string
		product string
		version string
		osHint  string
	}
	cases := []struct {
		name   string
		banner string
		port   uint32
		want   want
	}{
		{
			// Metasploitable's VNC greets with the RFB protocol version on
			// connect — a banner, not a probe. Protocol certain, product not.
			name:   "vnc rfb greeting",
			banner: "RFB 003.003\n",
			port:   5900,
			want:   want{service: "vnc"},
		},
		{
			// UnrealIRCd on Metasploitable sends a NOTICE AUTH before the client
			// says anything. Protocol certain, product not.
			name:   "irc notice auth",
			banner: ":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...\r\n",
			port:   6667,
			want:   want{service: "irc"},
		},
		{
			// Regression: the SSH/Ubuntu case that already works and carries the
			// OS hint B21 consumes.
			name:   "openssh ubuntu",
			banner: "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\r\n",
			port:   22,
			want:   want{service: "ssh", product: "OpenSSH", version: "4.7p1", osHint: "Debian"},
		},
		{
			// Regression: vsftpd names its version in the FTP greeting.
			name:   "vsftpd",
			banner: "220 (vsFTPd 2.3.4)\r\n",
			port:   21,
			want:   want{service: "ftp", product: "vsftpd", version: "2.3.4"},
		},
	}

	matches := BuiltinBannerMatches()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := classify(matches, tc.banner, tc.port)
			if !ok {
				t.Fatalf("banner %q on port %d matched nothing; want service %q",
					tc.banner, tc.port, tc.want.service)
			}
			if got.service != tc.want.service || got.product != tc.want.product ||
				got.version != tc.want.version || got.osHint != tc.want.osHint {
				t.Errorf("banner %q -> %+v, want %+v", tc.banner, got, tc.want)
			}
		})
	}
}

type classified struct {
	service string
	product string
	version string
	osHint  string
}

// classify mirrors the engine's evaluate: first port-applicable rule whose
// pattern matches wins, with version/product/info lifted from named groups.
func classify(matches []enginewire.Match, banner string, port uint32) (classified, bool) {
	for _, m := range matches {
		if len(m.Ports) > 0 {
			ok := false
			for _, p := range m.Ports {
				if p == port {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			continue
		}
		hit := re.FindStringSubmatch(banner)
		if hit == nil {
			continue
		}
		c := classified{service: m.Service, product: m.Product, osHint: m.OSHint}
		for i, name := range re.SubexpNames() {
			if i >= len(hit) || hit[i] == "" {
				continue
			}
			switch name {
			case "version":
				c.version = strings.TrimSpace(hit[i])
			case "product":
				c.product = strings.TrimSpace(hit[i])
			}
		}
		return c, true
	}
	return classified{}, false
}

// TestMetasploitableVersionCoverageMeasured runs Metasploitable 2's actual
// safe-mode banners through the built-in matcher and records, per service,
// whether a services.VERSION is produced — the number release resolution
// actually gets (ADR-064). It reconciles the session-26 "6-7/11 identified"
// figure: that counted services IDENTIFIED (any method), which includes
// versionless soft-matches (telnet, VNC, IRC) and product-only (Postfix). Release
// resolution needs a VERSION, and this measures how many carry one. Also a
// regression lock: the four version-yielders must keep yielding.
func TestMetasploitableVersionCoverageMeasured(t *testing.T) {
	matches := BuiltinBannerMatches()
	// The safe-mode passive banners Metasploitable emits on connect. HTTP, SMB,
	// PostgreSQL and RPCbind send NOTHING unsolicited (they wait for the client),
	// so in safe mode they are method:none — represented by an empty banner.
	cases := []struct {
		svc, banner string
		port        uint32
	}{
		{"ftp/vsftpd", "220 (vsFTPd 2.3.4)\r\n", 21},
		{"ssh", "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\r\n", 22},
		{"telnet", "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23", 23},
		{"smtp/postfix", "220 metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n", 25},
		{"http/apache", "", 80}, // no passive banner: probe-gated (intrusive only)
		{"smb/samba", "", 139},  // no passive banner + no Samba matcher anywhere
		{"mysql", "\x36\x00\x00\x00\x0a5.0.51a-3ubuntu5\x00\x2b", 3306},
		{"postgresql", "", 5432}, // no passive banner
		{"vnc", "RFB 003.003\n", 5900},
		{"irc/unrealircd", ":irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...\r\n", 6667},
		{"ftp/proftpd", "220 ProFTPD 1.3.1 Server (Debian)\r\n", 2121},
	}
	withVersion := map[string]bool{}
	for _, c := range cases {
		if c.banner == "" {
			t.Logf("%-16s port %-5d -> NO passive banner (method:none in safe mode)", c.svc, c.port)
			continue
		}
		got, ok := classify(matches, c.banner, c.port)
		switch {
		case !ok:
			t.Logf("%-16s port %-5d -> matched NOTHING", c.svc, c.port)
		case got.version != "":
			withVersion[c.svc] = true
			t.Logf("%-16s port %-5d -> VERSION  %s %s", c.svc, c.port, got.product, got.version)
		case got.product != "":
			t.Logf("%-16s port %-5d -> product-only (no version)  %s", c.svc, c.port, got.product)
		default:
			t.Logf("%-16s port %-5d -> soft/service-only (%s)", c.svc, c.port, got.service)
		}
	}
	t.Logf("SERVICES YIELDING A VERSION (safe mode): %d — %v", len(withVersion), keysOf(withVersion))
	// Regression lock: these four must keep yielding a version.
	for _, svc := range []string{"ftp/vsftpd", "ssh", "mysql", "ftp/proftpd"} {
		if !withVersion[svc] {
			t.Errorf("%s no longer yields a version — a corpus matcher regressed", svc)
		}
	}

	// The fifth version-yielder is INTRUSIVE, not passive: HTTP sends no
	// unsolicited banner, but the http-head PROBE reads the Server header, and the
	// httpMatches rule lifts Apache's version. So on Metasploitable the corpus can
	// version-identify 5 of 11 services — four in safe mode, plus Apache under
	// intrusive probing. Measured here so "5 of 11" is measured, not asserted.
	apache, ok := classify(httpMatches(),
		"HTTP/1.1 200 OK\r\nServer: Apache/2.2.8 (Ubuntu) DAV/2\r\n\r\n", 80)
	if !ok || apache.version != "2.2.8" {
		t.Errorf("intrusive HTTP probe should lift Apache 2.2.8, got %+v (ok=%t)", apache, ok)
	}
	t.Logf("SERVICES YIELDING A VERSION (incl. intrusive HTTP): %d of 11 — the safe four plus Apache httpd %s (product %q)",
		len(withVersion)+1, apache.version, apache.product)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
