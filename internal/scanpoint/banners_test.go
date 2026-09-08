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
