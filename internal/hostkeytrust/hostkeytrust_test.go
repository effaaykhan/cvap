package hostkeytrust

import (
	"errors"
	"strings"
	"testing"
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
