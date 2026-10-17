package target

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func mustMatch(t *testing.T, raw string) Canonical {
	t.Helper()
	c, ok := Matches(raw)
	if !ok {
		t.Fatalf("%q is not canonical", raw)
	}
	return c
}

// TestACoreAddressOrARangeCoveringItIsContained: the refusal covers the address
// itself and every prefix that would sweep it, and nothing else.
func TestACoreAddressOrARangeCoveringItIsContained(t *testing.T) {
	e, err := NewCoreEndpoints(t.Context(), []string{"10.0.0.5:8443", "10.0.0.5:8444", "[2001:db8::7]:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		raw  string
		want bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.0/24", true},
		{"10.0.0.4/31", true},
		{"10.0.0.6", false},
		{"10.0.0.6/31", false},
		{"2001:db8::7", true},
		{"2001:db8::/64", true},
		{"2001:db8::8", false},
	} {
		if got := e.Contains(mustMatch(t, c.raw)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestANameIsResolvedOnceAndAFailureIsAnError: a Core endpoint given as a name is
// refused by address, and a name that will not resolve must not produce a set
// that silently refuses nothing.
func TestANameIsResolvedOnceAndAFailureIsAnError(t *testing.T) {
	calls := 0
	ok := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
	}
	e, err := NewCoreEndpoints(t.Context(), []string{"core.example:8444", "core.example:8443"}, ok)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Contains(mustMatch(t, "192.0.2.9")) {
		t.Error("the resolved Core address is not refused")
	}
	if calls != 2 {
		t.Errorf("resolved %d times, want once per endpoint at construction", calls)
	}
	fail := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }
	if _, err := NewCoreEndpoints(t.Context(), []string{"core.example:8444"}, fail); err == nil {
		t.Error("an unresolvable Core endpoint produced a set instead of an error")
	}
	empty := func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	if _, err := NewCoreEndpoints(t.Context(), []string{"core.example:8444"}, empty); err == nil {
		t.Error("a name resolving to nothing produced a set instead of an error")
	}
}

// TestListenAddressesAreSkippedAndAnEmptySetIsRefused: ":8444" and
// "0.0.0.0:8444" say where Core listens, not where it can be reached; if that
// is all there is, there is no set to enforce and that is an error.
func TestListenAddressesAreSkippedAndAnEmptySetIsRefused(t *testing.T) {
	if _, err := NewCoreEndpoints(t.Context(), []string{":8444", "0.0.0.0:8443", "[::]:8445", ""}, nil); !errors.Is(err, ErrNoCoreEndpoint) {
		t.Errorf("only listen addresses: err = %v, want ErrNoCoreEndpoint", err)
	}
	e, err := NewCoreEndpoints(t.Context(), []string{":8444", "127.0.0.1:8443"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Addrs(); len(got) != 1 || got[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("Addrs() = %v, want [127.0.0.1]", got)
	}
}

// TestAV4MappedEndpointSpellingIsRefused: an IPv4-mapped IPv6 spelling in E is
// refused, because Go would unmap it to v4 while the holder installs it as a v6
// exemption, so the two enforcement layers would disagree (ADR-111). The refusal
// is semantic (Is4In6), not a dotted-quad text match, so EVERY equivalent
// spelling is refused - the all-hex ::ffff:0a00:0005 included, which a textual
// check missed. Ordinary IPv4 and native IPv6 are still accepted. A v4-mapped
// SCAN TARGET is still refused, because Canonicalise unmaps it to plain v4
// before it reaches Contains.
func TestAV4MappedEndpointSpellingIsRefused(t *testing.T) {
	// Every spelling of the same IPv4-mapped address (10.0.0.5) is refused.
	for _, mapped := range []string{
		"[::ffff:10.0.0.5]:8444",          // dotted
		"[::ffff:0a00:0005]:8444",         // all-hex, zero-padded
		"[::ffff:a00:5]:8444",             // all-hex, minimal
		"[0:0:0:0:0:ffff:0a00:0005]:8444", // fully expanded, all-hex
		"[0:0:0:0:0:ffff:10.0.0.5]:8444",  // fully expanded, dotted
		"[0::ffff:0a00:0005]:8444",        // partially compressed
	} {
		if _, err := NewCoreEndpoints(t.Context(), []string{mapped}, nil); err == nil {
			t.Errorf("v4-mapped endpoint spelling %q was accepted; it must be refused (ADR-111)", mapped)
		}
	}
	// Positive controls: ordinary IPv4 and native IPv6 - including a native
	// address that merely contains an ffff group - are still accepted.
	for _, ok := range []string{"10.0.0.5:8444", "[2001:db8::10]:8444", "[2001:db8::ffff:1:2]:8444", "[::ffff:0:1:2:3]:8444"} {
		if _, err := NewCoreEndpoints(t.Context(), []string{ok}, nil); err != nil {
			t.Errorf("%q is an ordinary IPv4/native IPv6 endpoint but was refused: %v", ok, err)
		}
	}
	// The safe direction survives: a plain-v4 Core endpoint still catches a
	// v4-mapped scan-target spelling, since the target canonicalises to v4.
	e, err := NewCoreEndpoints(t.Context(), []string{"10.0.0.5:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"::ffff:10.0.0.5", "::ffff:0a00:0005"} {
		c, err := Canonicalise(spelling)
		if err != nil {
			t.Fatalf("Canonicalise(%s): %v", spelling, err)
		}
		if !e.Contains(c) {
			t.Errorf("a v4-mapped scan target %q is not refused against the plain v4 Core address", spelling)
		}
	}
}

// TestCoversIsEverExemptAddressBeingRefused: Covers is what the Scan Point's
// startup cross-check rests on - one direction only, by address identity. A
// v4-mapped spelling is refused at parse (TestAV4MappedEndpointSpellingIsRefused)
// and so never reaches Covers.
func TestCoversIsEveryExemptAddressBeingRefused(t *testing.T) {
	refusal, err := NewCoreEndpoints(t.Context(), []string{"192.0.2.10:8443", "[2001:db8::10]:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		exempt string
		covers bool
	}{
		{"192.0.2.10:8443", true},
		{"[2001:db8::10]:8443", true},
		{"192.0.2.11:8443", false},
		{"192.0.2.10:8443,192.0.2.11:8443", false},
	} {
		exempt, err := NewCoreEndpoints(t.Context(), splitComma(c.exempt), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := refusal.Covers(exempt); got != c.covers {
			t.Errorf("Covers(%s) = %v, want %v (missing %v)", c.exempt, got, c.covers, refusal.Missing(exempt))
		}
	}
}

func splitComma(s string) []string { return strings.Split(s, ",") }
