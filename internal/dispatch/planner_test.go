package dispatch

import (
	"errors"
	"strings"
	"testing"

	"github.com/effaaykhan/cvap/internal/target"
)

// TestExpansionProducesCanonicalFormsOnly.
//
// The property ADR-044 rests on: every string written to scan_tasks.task_target
// is one the scan point's own canonicalisation will reproduce byte for byte.
// A form that merely LOOKS canonical would pass a validator and fail this.
func TestExpansionProducesCanonicalFormsOnly(t *testing.T) {
	for _, declared := range []string{
		"192.0.2.5",
		"192.0.2.5:443",
		"[192.0.2.5]",
		"192.0.2.5.",
		"::ffff:192.0.2.5",
		"https://scanner.corp.example/status",
		"SCANNER.CORP.EXAMPLE",
		"192.0.2.0/30",
		"  192.0.2.7  ",
	} {
		t.Run(declared, func(t *testing.T) {
			got, err := expand(declared)
			if err != nil {
				t.Fatalf("expand(%q): %v", declared, err)
			}
			if len(got) == 0 {
				t.Fatal("expanded to nothing")
			}
			for _, v := range got {
				// The runtime's exact question, run here.
				if _, ok := target.Matches(v); !ok {
					t.Errorf("planning produced %q, which is not its own canonical form. The "+
						"scan point re-computes and compares, so this target would be refused "+
						"at the second enforcement site and take its whole job with it.", v)
				}
			}
		})
	}
}

// TestFiveSpellingsOfOneHostBecomeOneString is the landmine ADR-040 recorded and
// ADR-044 closed.
//
// Before canonicalisation at planning, these reached an engine as five distinct
// strings naming one host — so ADR-024's per-target rate ceiling and ADR-021's
// fragile cap would each have divided by five.
func TestFiveSpellingsOfOneHostBecomeOneString(t *testing.T) {
	want := "192.0.2.5"
	for _, spelling := range []string{
		"192.0.2.5", "192.0.2.5:443", "192.0.2.5.", "[192.0.2.5]", "https://192.0.2.5/",
	} {
		got, err := expand(spelling)
		if err != nil {
			t.Fatalf("expand(%q): %v", spelling, err)
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("expand(%q) = %v, want [%s]. Five spellings of one host must become one "+
				"string, or every per-target budget divides by the number of spellings present.",
				spelling, got, want)
		}
	}
}

// TestAPrefixBecomesItsAddresses, including the network and broadcast ones.
//
// The inclusion is a decision, not an oversight: skipping them is under-scanning
// that reports as a clean run, and directed broadcasts have been dropped by
// default since RFC 2644. Rate limiting is the control for amplification.
func TestAPrefixBecomesItsAddresses(t *testing.T) {
	got, err := expand("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("expand(192.0.2.0/30) = %v, want %v", got, want)
	}
}

// TestAnUnmaskedPrefixExpandsFromItsNetworkAddress. 192.0.2.5/30 names the same
// four hosts as 192.0.2.4/30, and a planner that started at .5 would scan three.
func TestAnUnmaskedPrefixExpandsFromItsNetworkAddress(t *testing.T) {
	got, err := expand("192.0.2.5/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("expand(192.0.2.5/30) = %v, want %v", got, want)
	}
}

// TestAPrefixTooLargeIsRefusedRatherThanTruncated.
//
// Truncation is the failure this codebase refuses everywhere: a /8 planned as
// its first 65,536 addresses reports a clean run over coverage it did not have.
func TestAPrefixTooLargeIsRefusedRatherThanTruncated(t *testing.T) {
	for _, p := range []string{"10.0.0.0/8", "2001:db8::/64", "::/0"} {
		got, err := expand(p)
		if !errors.Is(err, ErrTargetTooLarge) {
			t.Errorf("expand(%q) = %v, %v; want ErrTargetTooLarge", p, got, err)
		}
		if got != nil {
			t.Errorf("expand(%q) returned %d targets alongside its error", p, len(got))
		}
	}
}

// TestTheLargestPermittedPrefixIsPlanned. The bound is a real number, not a
// guard that refuses everything near it.
func TestTheLargestPermittedPrefixIsPlanned(t *testing.T) {
	got, err := expand("10.1.0.0/16")
	if err != nil {
		t.Fatalf("a /16 is exactly the bound and must plan: %v", err)
	}
	if len(got) != MaxAddressesPerTarget {
		t.Errorf("a /16 expanded to %d, want %d", len(got), MaxAddressesPerTarget)
	}
}

// TestAnAddressShapedTargetThatWillNotParseIsRefused. ADR-040, moved to planning
// where the operator can be told about it.
func TestAnAddressShapedTargetThatWillNotParseIsRefused(t *testing.T) {
	for _, bad := range []string{
		"192.000.2.5",
		"0xC0.0x00.0x02.0x05",
		"192.0.2.1-50",
		"192.0.2.5,192.0.2.6",
		"192.0.2.5.6.7",
	} {
		if got, err := expand(bad); !errors.Is(err, ErrTargetNotCanonical) {
			t.Errorf("expand(%q) = %v, %v; want ErrTargetNotCanonical", bad, got, err)
		}
	}
}

// TestAHostnameIsStillAHostname. The refusal above must not swallow the ordinary
// case — ADR-040 rejected "refuse everything that is not an address" precisely
// because it makes a whole match type unusable.
func TestAHostnameIsStillAHostname(t *testing.T) {
	for _, name := range []string{
		"scanner.corp.example", "dead.beef", "1host.corp.example", "cafe.example",
	} {
		got, err := expand(name)
		if err != nil {
			t.Errorf("expand(%q): %v — this is a legitimate hostname target", name, err)
			continue
		}
		if len(got) != 1 || got[0] != strings.ToLower(name) {
			t.Errorf("expand(%q) = %v", name, got)
		}
	}
}
