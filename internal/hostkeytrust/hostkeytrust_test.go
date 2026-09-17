package hostkeytrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestComposeThenParseRoundTripsTheSource(t *testing.T) {
	for _, src := range []Source{SourceOperator, SourceObserved} {
		wire, err := Compose(src, "10.0.0.9 SHA256:abc\n")
		if err != nil {
			t.Fatalf("%s: compose: %v", src, err)
		}
		if !strings.HasPrefix(wire, HeaderPrefix+string(src)+"\n") {
			t.Fatalf("%s: header missing from %q", src, wire)
		}
		got, material, err := Parse(wire)
		if err != nil {
			t.Fatalf("%s: parse: %v", src, err)
		}
		if got != src {
			t.Errorf("source = %q, want %q", got, src)
		}
		if strings.TrimSpace(material) != "10.0.0.9 SHA256:abc" {
			t.Errorf("material = %q", material)
		}
	}
}

// The TOFU shape is refused at BOTH ends: Core will not compose it, and a
// runtime handed it (by a Core that skipped Compose) refuses it by name.
func TestEmptyMaterialIsRefusedAsTOFU(t *testing.T) {
	if _, err := Compose(SourceObserved, "\n# only a comment\n"); !errors.Is(err, ErrNoMaterial) {
		t.Errorf("compose with no material: err = %v, want ErrNoMaterial", err)
	}
	if _, _, err := Parse(HeaderPrefix + "observed\n# nothing\n"); !errors.Is(err, ErrNoMaterial) {
		t.Errorf("parse with no material: err = %v, want ErrNoMaterial", err)
	}
}

func TestParseRefusesAMissingOrUnknownHeader(t *testing.T) {
	if _, _, err := Parse("10.0.0.9 SHA256:abc\n"); !errors.Is(err, ErrNoHeader) {
		t.Errorf("no header: err = %v, want ErrNoHeader", err)
	}
	if _, _, err := Parse(HeaderPrefix + "tofu\n10.0.0.9 SHA256:abc\n"); !errors.Is(err, ErrUnknownSource) {
		t.Errorf("unknown source: err = %v, want ErrUnknownSource", err)
	}
	if _, err := Compose(Source("tofu"), "x y z"); !errors.Is(err, ErrUnknownSource) {
		t.Errorf("compose unknown source: err = %v, want ErrUnknownSource", err)
	}
}

func TestLinesCoveringBindsPinsToTheirHost(t *testing.T) {
	pin := "# operator pins\n10.0.0.1 ssh-ed25519 AAAA one\n192.0.2.7,alias ssh-ed25519 BBBB two\n[192.0.2.7]:22 SHA256:xyz\n|1|hashed ssh-ed25519 CCCC\nSHA256:bare\n"
	got := LinesCovering(pin, "192.0.2.7")
	if len(got) != 2 {
		t.Fatalf("lines covering 192.0.2.7 = %q, want the two that name it", got)
	}
	if n := len(LinesCovering(pin, "198.51.100.4")); n != 0 {
		t.Fatalf("an unrelated target was covered by %d line(s)", n)
	}
}

// ValidatePin accepts plain known_hosts lines and nothing else (ADR-100): a
// marker, a hashed host, a malformed key, or no key at all is refused by name,
// and the fingerprints of what was accepted come back for the audit record.
func TestValidatePinAcceptsPlainLinesOnly(t *testing.T) {
	line := testKnownHostsLine(t, "10.0.0.5")
	canon, fps, err := ValidatePin("# a comment\n" + line + "\n\n")
	if err != nil || len(fps) != 1 || canon != line+"\n" {
		t.Fatalf("plain line: canon=%q fps=%v err=%v", canon, fps, err)
	}
	if _, _, err := ValidatePin("[10.0.0.5]:22 " + line[strings.Index(line, " ")+1:]); err != nil {
		t.Errorf("[host]:22 is the dialled port and must be accepted: %v", err)
	}
	// A refusal echoes at most a token of the caller's line.
	if _, _, err := ValidatePin("@" + strings.Repeat("m", 60000) + " " + line); err == nil || len(err.Error()) > 200 {
		t.Errorf("marker refusal echoes the caller's line: err len %d", len(err.Error()))
	}
	for name, bad := range map[string]string{
		"empty":        "",
		"comment only": "# nothing\n",
		"marker":       "@cert-authority " + line,
		"hashed host":  "|1|abc=|def= " + line[strings.Index(line, " ")+1:],
		"garbage":      "10.0.0.5 ssh-ed25519 notbase64!!\n",
		"too long":     strings.Repeat(line+"\n", MaxPinLines+1),
		// A pattern or a negation matches no target by exact name, so it pins
		// nothing an engine can use and every job it meant to cover refuses.
		"wildcard host": "10.0.0.* " + line[strings.Index(line, " ")+1:],
		"any host":      "* " + line[strings.Index(line, " ")+1:],
		"negated host":  "!10.0.0.5 " + line[strings.Index(line, " ")+1:],
		// A control character reaches the text column as a 500; a port the
		// engine does not dial covers nothing and turns the profile off.
		"nul in host": "10.0.0.5\x00evil " + line[strings.Index(line, " ")+1:],
		"other port":  "[10.0.0.5]:2222 " + line[strings.Index(line, " ")+1:],
	} {
		if _, _, err := ValidatePin(bad); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
}

// testKnownHostsLine is a real ed25519 known_hosts line for host.
func testKnownHostsLine(t *testing.T, host string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return host + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}
