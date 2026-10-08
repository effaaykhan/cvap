package target

import (
	"context"
	"errors"
	"net/netip"
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

// TestAV4MappedFormIsTheSameAddress: ::ffff:10.0.0.5 is 10.0.0.5 on the wire.
func TestAV4MappedFormIsTheSameAddress(t *testing.T) {
	e, err := NewCoreEndpoints(t.Context(), []string{"[::ffff:10.0.0.5]:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Contains(mustMatch(t, "10.0.0.5")) {
		t.Error("a v4-mapped Core endpoint does not refuse the plain v4 address")
	}
}
