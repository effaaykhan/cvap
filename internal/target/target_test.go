package target

import (
	"strings"
	"testing"
)

// The apparatus in this package is what three consecutive scan-safety audits
// found bypasses in, and until now it was tested only indirectly through
// scopetest drivers in other packages. These are the direct tests.

// TestCanonicaliseIsIdempotent is the property every other site depends on.
//
// The scan point re-canonicalises and requires equality with what arrived
// (ADR-044). If Canonicalise(Canonicalise(x)) ever differed from Canonicalise(x),
// every target of that shape would be refused at the second site and take its
// whole job with it — so this is not a tidiness property, it is the one that
// makes the two-site arrangement work at all.
func TestCanonicaliseIsIdempotent(t *testing.T) {
	for _, raw := range []string{
		"192.0.2.5", "192.0.2.5:443", "[192.0.2.5]", "192.0.2.5.", "  192.0.2.5  ",
		"::ffff:192.0.2.5", "[::ffff:192.0.2.5]:443", "2001:db8::1", "[2001:db8::1]:8080",
		"fe80::1%eth0", "192.0.2.0/24", "192.0.2.5/32", "2001:db8::/32", "2001:db8::1/128",
		"scanner.corp.example", "SCANNER.CORP.EXAMPLE", "scanner.corp.example.",
		"https://scanner.corp.example/status", "http://scanner.corp.example:8080/a/b?c=d#e",
		"dead.beef", "1host.corp.example", "xn--nxasmq6b.example",
	} {
		t.Run(raw, func(t *testing.T) {
			once, err := Canonicalise(raw)
			if err != nil {
				t.Fatalf("Canonicalise(%q): %v", raw, err)
			}
			twice, err := Canonicalise(once.Value)
			if err != nil {
				t.Fatalf("Canonicalise(%q) — the canonical form of %q — failed: %v", once.Value, raw, err)
			}
			if twice.Value != once.Value {
				t.Errorf("not idempotent: %q -> %q -> %q", raw, once.Value, twice.Value)
			}
			if twice.Kind != once.Kind {
				t.Errorf("kind changed on the second pass: %v then %v", once.Kind, twice.Kind)
			}
			// The whole point, stated as the runtime states it.
			if _, ok := Matches(once.Value); !ok {
				t.Errorf("Matches(%q) is false for a value this package produced; the scan "+
					"point would refuse a target Core planned", once.Value)
			}
		})
	}
}

// TestSpellingsOfOneHostShareOneCanonicalForm.
func TestSpellingsOfOneHostShareOneCanonicalForm(t *testing.T) {
	for _, group := range [][]string{
		{"192.0.2.5", "192.0.2.5:443", "192.0.2.5.", "[192.0.2.5]", "https://192.0.2.5/",
			"  192.0.2.5  ", "::ffff:192.0.2.5", "192.0.2.5/32", "[::ffff:192.0.2.5]:80"},
		{"2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:443", "2001:DB8::1", "2001:db8:0:0:0:0:0:1",
			"2001:db8::1/128", "https://[2001:db8::1]/x"},
		{"scanner.corp.example", "SCANNER.corp.example", "scanner.corp.example.",
			"https://scanner.corp.example/status", "scanner.corp.example:8443"},
	} {
		want, err := Canonicalise(group[0])
		if err != nil {
			t.Fatalf("Canonicalise(%q): %v", group[0], err)
		}
		for _, spelling := range group[1:] {
			got, err := Canonicalise(spelling)
			if err != nil {
				t.Errorf("Canonicalise(%q): %v", spelling, err)
				continue
			}
			if got.Value != want.Value {
				t.Errorf("%q canonicalises to %q; %q canonicalises to %q. These name one host.",
					group[0], want.Value, spelling, got.Value)
			}
		}
	}
}

// TestAZoneIdentifierDoesNotCarryATargetOutOfScope.
//
// A zone names a local interface, not a different host. Before it was stripped,
// netip.Prefix.Contains returned false for ANY zoned address and Addr equality
// included the zone, so `fe80::1%eth0` was not excluded by a rule naming
// `fe80::1` and no CIDR exclusion could reach a zoned target at all.
func TestAZoneIdentifierDoesNotCarryATargetOutOfScope(t *testing.T) {
	zoned, err := Canonicalise("fe80::1%eth0")
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	bare, err := Canonicalise("fe80::1")
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	if zoned.Value != bare.Value || zoned.Addr != bare.Addr {
		t.Errorf("fe80::1%%eth0 canonicalises to %q and fe80::1 to %q; a zone identifies an "+
			"interface, not a host", zoned.Value, bare.Value)
	}
}

// TestKindIsWhatTheCallerNeedsToDecide.
func TestKindIsWhatTheCallerNeedsToDecide(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Kind
	}{
		{"192.0.2.5", KindAddress},
		{"192.0.2.5/32", KindAddress}, // a full-length prefix names one host
		{"2001:db8::1/128", KindAddress},
		{"192.0.2.0/24", KindPrefix},
		{"2001:db8::/32", KindPrefix},
		{"scanner.corp.example", KindHostname},
		{"https://scanner.corp.example/x", KindHostname},
	} {
		got, err := Canonicalise(tc.raw)
		if err != nil {
			t.Errorf("Canonicalise(%q): %v", tc.raw, err)
			continue
		}
		if got.Kind != tc.want {
			t.Errorf("Canonicalise(%q).Kind = %v, want %v", tc.raw, got.Kind, tc.want)
		}
	}
}

// TestAPrefixIsMasked. 192.0.2.5/24 and 192.0.2.0/24 name the same range, and a
// planner that expanded from .5 would scan a range short of its first addresses.
func TestAPrefixIsMasked(t *testing.T) {
	got, err := Canonicalise("192.0.2.5/24")
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "192.0.2.0/24" {
		t.Errorf("Canonicalise(192.0.2.5/24) = %q, want 192.0.2.0/24", got.Value)
	}
}

// TestAddressShapedStringsThatWillNotParseAreRefused is ADR-040's third branch.
//
// Every entry reaches 192.0.2.5, or a range containing it, under inet_aton
// semantics — and each walked past the first version of the shape test, which
// asked whether the string was digits, dots and slashes.
func TestAddressShapedStringsThatWillNotParseAreRefused(t *testing.T) {
	for _, raw := range []string{
		"192.000.2.5",
		"0xC0000205",
		"0xC0.0x00.0x02.0x05",
		"192.0.0x2.5",
		"192.0.2.1-50",
		"192.0.2.5,192.0.2.6",
		"3221225989",
		"0300.0000.0002.0005",
		"192.0.2.5.6",
		"[192.0.2.5",
		"192.0.2.5]",
		"１９２.0.2.5", // fullwidth digits
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := Canonicalise(raw)
			if err == nil {
				t.Errorf("Canonicalise(%q) = %q with no error. A string that NAMES an address "+
					"and will not parse as one must be refused, not compared as a hostname — "+
					"comparing it as a hostname is how an address exclusion gets walked past.",
					raw, got.Value)
			}
		})
	}
}

// TestBareHexIsNotANumber, which is why the shape test does not over-refuse.
//
// ADR-040 rejected "refuse everything that does not parse as an address"
// precisely because it makes hostname — an accepted scope_match_type with rules
// already written against it — unusable.
func TestBareHexIsNotANumber(t *testing.T) {
	for _, raw := range []string{
		"dead.beef",
		"cafe.example",
		"1host.corp.example",
		"a1.b2.example",
		"scanner.corp.example",
		"localhost",
		"host-1.corp.example",
	} {
		got, err := Canonicalise(raw)
		if err != nil {
			t.Errorf("Canonicalise(%q): %v — this is a legitimate hostname", raw, err)
			continue
		}
		if got.Kind != KindHostname {
			t.Errorf("Canonicalise(%q).Kind = %v, want hostname", raw, got.Kind)
		}
	}
}

// TestLooksLikeAddressIsAComponentTest, not a character-set test.
//
// Exported, and until now untested directly. The distinction is ADR-040's:
// asking whether every COMPONENT parses as a number generalises, while asking
// whether the string is made of digits and dots is an enumeration of two
// spellings.
func TestLooksLikeAddressIsAComponentTest(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want bool
	}{
		{"192.0.2.5", true},
		{"192.000.2.5", true},
		{"0xC0.0x00.0x02.0x05", true},
		{"0300.0000.0002.0005", true},
		{"3221225989", true},
		{"192.0.2.1-50", true},
		{"192.0.2.5,192.0.2.6", true},
		{"192.0.2.0/24", true},
		{"2001:db8::1", true}, // a colon is decisive on its own
		{"[anything]", true},  // so is a bracket
		{"１９２.0.2.5", true},

		{"dead.beef", false},
		{"cafe.example", false},
		{"1host.corp.example", false},
		{"scanner.corp.example", false},
		{"localhost", false},
		{"", false},
	} {
		if got := LooksLikeAddress(tc.s); got != tc.want {
			t.Errorf("LooksLikeAddress(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// TestMatchesComparesTheReceivedBytesUnchanged.
//
// ============================================================================
// The property the whole second enforcement site rests on.
// ============================================================================
//
// The first draft of Matches trimmed before comparing, so " 192.0.2.5" was
// reported as canonical. Trimming — or any tidying before the equality test — is
// the tolerance that turns a re-computation back into a validator.
func TestMatchesComparesTheReceivedBytesUnchanged(t *testing.T) {
	for _, raw := range []string{
		" 192.0.2.5",
		"192.0.2.5 ",
		"\t192.0.2.5",
		"192.0.2.5:443",
		"[192.0.2.5]",
		"192.0.2.5.",
		"::ffff:192.0.2.5",
		"SCANNER.corp.example",
		"https://scanner.corp.example/x",
		"192.0.2.5/24",
	} {
		if _, ok := Matches(raw); ok {
			t.Errorf("Matches(%q) is true. It is not this package's own canonical form of "+
				"itself, so the second site would be accepting a value it did not compute.", raw)
		}
	}
	for _, raw := range []string{"192.0.2.5", "2001:db8::1", "scanner.corp.example", "192.0.2.0/24"} {
		if _, ok := Matches(raw); !ok {
			t.Errorf("Matches(%q) is false for a canonical value", raw)
		}
	}
	// And an unparseable one is not canonical rather than an error the caller
	// has to distinguish: refusing is the only outcome either way.
	if _, ok := Matches("192.000.2.5"); ok {
		t.Error("Matches accepted a string that does not canonicalise")
	}
}

// TestLengthIsBounded. A target arrives from a database column with no length
// constraint, and every function here is called on the send path.
func TestLengthIsBounded(t *testing.T) {
	long := strings.Repeat("a", MaxLength) + ".example"
	if _, err := Canonicalise(long); err == nil {
		t.Errorf("a %d-character target was accepted; MaxLength is %d", len(long), MaxLength)
	}
	if _, err := Canonicalise(""); err == nil {
		t.Error("an empty target was accepted")
	}
	if _, err := Canonicalise("   "); err == nil {
		t.Error("a whitespace-only target was accepted")
	}
}

// TestAURLIsJudgedOnTheHostItWouldReach, and only on that.
//
// A path, query or fragment selects what is REQUESTED from a host rather than
// which host — that is safety_mode's question (ADR-021), not scope's. Userinfo
// is not touched either, because it changes who the request authenticates as.
func TestAURLIsJudgedOnTheHostItWouldReach(t *testing.T) {
	for _, raw := range []string{
		"https://printer.corp.example/setup",
		"http://printer.corp.example:8080/setup?reset=1#top",
		"https://printer.corp.example",
	} {
		got, err := Canonicalise(raw)
		if err != nil {
			t.Errorf("Canonicalise(%q): %v", raw, err)
			continue
		}
		if got.Value != "printer.corp.example" {
			t.Errorf("Canonicalise(%q) = %q, want printer.corp.example", raw, got.Value)
		}
	}
}

// TestAMalformedURLDoesNotCanonicaliseToItsScheme.
//
// The SplitHostPort defect: "http://" split as host "http" and port "//",
// which then normalised to the scheme name and would have been compared as a
// hostname called "http".
func TestAMalformedURLDoesNotCanonicaliseToItsScheme(t *testing.T) {
	for _, raw := range []string{"http://", "https://", "http://:8080", "https://:/x"} {
		got, err := Canonicalise(raw)
		if err == nil && (got.Value == "http" || got.Value == "https") {
			t.Errorf("Canonicalise(%q) = %q — the scheme became the host", raw, got.Value)
		}
	}
}

// TestAPortIsNotAHost. validPort exists because SplitHostPort accepts anything
// after the colon.
func TestAPortIsNotAHost(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"scanner.corp.example:443", "scanner.corp.example"},
		{"scanner.corp.example:0", "scanner.corp.example"},
		{"scanner.corp.example:65535", "scanner.corp.example"},
	} {
		got, err := Canonicalise(tc.raw)
		if err != nil {
			t.Errorf("Canonicalise(%q): %v", tc.raw, err)
			continue
		}
		if got.Value != tc.want {
			t.Errorf("Canonicalise(%q) = %q, want %q", tc.raw, got.Value, tc.want)
		}
	}
	// Out of range, so the colon is not a port separator — and the result is
	// therefore a name containing a colon, which is refused rather than
	// silently truncated.
	if got, err := Canonicalise("scanner.corp.example:65536"); err == nil {
		t.Errorf("Canonicalise with an out-of-range port = %q, want a refusal", got.Value)
	}
}
