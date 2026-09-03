package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mutations, declared beside the tests that must kill them.
//
// Four of these were sabotage-tested by hand before `make mutate` covered Go —
// and one of the hand tests found a test that proved nothing: removing the
// translated-form extraction left the suite green, because every case was
// already caught by the 2000::/3 allowlist. That is exactly the thing that
// should not depend on somebody remembering to try it.
//
// mutate:subject internal/control/api/oidc_client.go
// mutate:test    ./internal/control/api/ -run TestLinkLocal|TestPrivateAddresses|TestTheAddresses|TestATranslated|TestTheIPv6Side|TestPublicAddresses|TestNonTCP|TestTheRefusalNames|TestEveryIdentityProvider|TestTheBoundedTransport
//
// mutate:case    the IPv6 allowlist is not applied
// mutate:old     if !globalUnicastV6.Contains(c) {
// mutate:new     if false {
//
// mutate:case    translated forms are not extracted
// mutate:old     candidates = append(candidates, target.TranslatedV4s(ip)...)
// mutate:new     _ = target.TranslatedV4s
//
// mutate:case    the private-issuer flag opens the whole registry, link-local included
// mutate:old     if allowPrivate && (r == reasonPrivate || r == reasonLoopback) {
// mutate:new     if allowPrivate {
//
// mutate:case    the v4 registry is not consulted
// mutate:old     r := specialPurposeV4(c)
// mutate:new     r := ""
//
// mutate:case    identity provider response bodies are unbounded
// mutate:old     Reader: io.LimitReader(resp.Body, b.max),
// mutate:new     Reader: resp.Body,
//
// The dial guard is the only thing standing between an operator-supplied issuer
// URL and Core's own network. It is tested directly, on the function the dialer
// actually calls, because every other way of reaching it goes through DNS.

// TestLinkLocalIsRefusedEvenWithPrivateIssuersAllowed.
//
// ============================================================================
// The one that matters. 169.254.169.254 is cloud instance metadata.
// ============================================================================
//
// An on-prem deployment legitimately needs 10.0.0.5, which is why
// AllowPrivateIssuers exists — and nobody legitimately needs the metadata
// service. If the two were one setting, turning on the reasonable half would
// hand a customer credentials for the machine this deployment runs on.
func TestLinkLocalIsRefusedEvenWithPrivateIssuersAllowed(t *testing.T) {
	for _, addr := range []string{
		"169.254.169.254:80", // AWS, GCP, Azure, DigitalOcean, Oracle
		"169.254.170.2:80",   // ECS task metadata
		"[fe80::1]:443",      // IPv6 link-local
		"[fe80::a00:27ff:fe00:1]:443",
	} {
		for _, allowPrivate := range []bool{false, true} {
			err := refuseUnsafeAddress("tcp", addr, allowPrivate)
			if err == nil {
				t.Errorf("refuseUnsafeAddress(%q, allowPrivate=%v) permitted it. Link-local is "+
					"where instance metadata lives; permitting it hands a customer credentials "+
					"for the machine Core runs on.", addr, allowPrivate)
			}
		}
	}
}

// TestPrivateAddressesAreRefusedByDefaultAndPermittedDeliberately.
func TestPrivateAddressesAreRefusedByDefaultAndPermittedDeliberately(t *testing.T) {
	private := []string{
		"10.0.0.5:443", "192.168.1.10:443", "172.16.0.1:443",
		"127.0.0.1:443", "[::1]:443",
	}
	for _, addr := range private {
		if err := refuseUnsafeAddress("tcp", addr, false); err == nil {
			t.Errorf("%s was permitted with AllowPrivateIssuers off", addr)
		}
		if err := refuseUnsafeAddress("tcp", addr, true); err != nil {
			t.Errorf("%s was refused with AllowPrivateIssuers on: %v. An on-prem deployment's "+
				"identity provider is normally on the internal network.", addr, err)
		}
	}
}

// TestTheAddressesAnAuditWalkedPastAreRefused.
//
// ============================================================================
// Every one of these was PERMITTED by the first version of the guard.
// ============================================================================
//
// The test that stood here before was worthless in a specific and instructive
// way: it listed six ranges that the guard's switch explicitly named, asserted
// they were refused, and reported that as evidence of an allowlist. It tested
// the blocklist's entries. An ADR-compliance pass ran the real function against
// the ranges the switch did NOT name and got every one of these back permitted.
func TestTheAddressesAnAuditWalkedPastAreRefused(t *testing.T) {
	for _, tc := range []struct{ addr, why string }{
		{"[2002:a00:1::1]:443", "6to4 carrying 10.0.0.1"},
		{"[64:ff9b::a00:1]:443", "NAT64 carrying 10.0.0.1 — an ordinary IPv6-only subnet feature"},
		{"[::a9fe:a9fe]:443", "the metadata address in v4-compatible form"},
		{"[2001:0:1:2:3:4:a9fe:a9fe]:443", "Teredo, whose embedded v4 is bitwise-inverted"},
		{"[fe80::5efe:a00:1]:443", "ISATAP carrying 10.0.0.1"},
		{"240.0.0.1:443", "class E, reserved"},
		{"0.1.2.3:443", "0.0.0.0/8, this-network space"},
		{"[fec0::1]:443", "site-local, deprecated but still routed on some networks"},
		{"[fc00::1]:443", "unique-local, the IPv6 RFC 1918"},
		{"192.0.0.1:443", "IETF protocol assignments"},
		{"198.18.0.1:443", "benchmarking space"},
		{"192.88.99.1:443", "the 6to4 relay anycast range"},
	} {
		if err := refuseUnsafeAddress("tcp", tc.addr, false); err == nil {
			t.Errorf("%s was permitted; it is %s", tc.addr, tc.why)
		}
	}
}

// TestATranslatedPrivateAddressIsRefusedTheWayAPlainOneIs.
//
// ADR-039's rule, applied to a refusal list. A guard that refuses 10.0.0.5 and
// permits 64:ff9b::a00:5 does not refuse 10.0.0.5 — it refuses one spelling of
// it, which is exactly the finding that ADR was written about, arrived at from
// the other side of the codebase.
func TestATranslatedPrivateAddressIsRefusedTheWayAPlainOneIs(t *testing.T) {
	// Every spelling of 10.0.0.5 that one of the five mechanisms can produce.
	spellings := []string{
		"10.0.0.5:443",
		"[::ffff:10.0.0.5]:443",      // v4-mapped: a notation, not a translation
		"[64:ff9b::a00:5]:443",       // NAT64
		"[2002:a00:5::1]:443",        // 6to4
		"[::10.0.0.5]:443",           // v4-compatible
		"[2001:db8::5efe:a00:5]:443", // ISATAP inside documentation space

		// ============================================================================
		// The one the 2000::/3 allowlist does NOT catch.
		// ============================================================================
		//
		// A GLOBAL prefix — allocated, routable, not special-purpose — carrying an
		// ISATAP interface identifier, whose low 32 bits are 10.0.0.5. The
		// allowlist permits the wrapper because the wrapper is a perfectly
		// ordinary public address; only extraction sees what is inside it.
		//
		// Sabotaging the TranslatedV4s call makes this line, and only this line,
		// fail — which is what says the extraction is load-bearing rather than
		// belt-and-braces. The first version of this test had no such case, so
		// removing the extraction entirely left it green.
		"[2a00:1450::5efe:a00:5]:443",
	}
	for _, addr := range spellings {
		if err := refuseUnsafeAddress("tcp", addr, false); err == nil {
			t.Errorf("%s was permitted with AllowPrivateIssuers off; it reaches 10.0.0.5", addr)
		}
	}
}

// TestTheIPv6SideIsAnAllowlist.
//
// One condition does the work: outside 2000::/3 is refused without anybody
// having had to think of the range. That is the property the old structure
// claimed and did not have, and it is why these pass without an entry each.
func TestTheIPv6SideIsAnAllowlist(t *testing.T) {
	for _, addr := range []string{
		"[100::1]:443",    // discard-only, RFC 6666
		"[4000::1]:443",   // unallocated
		"[8000::1]:443",   // unallocated
		"[fd00::1]:443",   // unique-local
		"[ff05::1:3]:443", // site-local multicast
		"[::2]:443",       // inside ::/128 neighbourhood, unallocated
	} {
		if err := refuseUnsafeAddress("tcp", addr, false); err == nil {
			t.Errorf("%s was permitted; only 2000::/3 is globally-routable IPv6 unicast", addr)
		}
	}
}

// TestPublicAddressesAreReachable. A guard that refuses everything is not a
// guard, it is an outage.
func TestPublicAddressesAreReachable(t *testing.T) {
	for _, addr := range []string{
		"93.184.216.34:443", // example.com
		"[2606:2800:220:1:248:1893:25c8:1946]:443",
		"8.8.8.8:443",
	} {
		for _, allowPrivate := range []bool{false, true} {
			if err := refuseUnsafeAddress("tcp", addr, allowPrivate); err != nil {
				t.Errorf("refuseUnsafeAddress(%q, %v) = %v; a public issuer must be reachable",
					addr, allowPrivate, err)
			}
		}
	}
}

// TestNonTCPAndUnparseableAreRefused. Deny by default: something this function
// does not understand has not been checked.
func TestNonTCPAndUnparseableAreRefused(t *testing.T) {
	if err := refuseUnsafeAddress("udp", "8.8.8.8:53", true); err == nil {
		t.Error("a udp connection was permitted")
	}
	if err := refuseUnsafeAddress("unix", "/var/run/x.sock", true); err == nil {
		t.Error("a unix socket was permitted")
	}
	for _, addr := range []string{"not-an-address", "", "idp.example.com:443"} {
		if err := refuseUnsafeAddress("tcp", addr, true); err == nil {
			t.Errorf("%q was permitted; the dialer hands Control a literal address, so a name "+
				"here means something resolved differently than expected", addr)
		}
	}
}

// TestTheRefusalNamesTheAddress, because an operator debugging a misconfigured
// issuer needs to know what it resolved to.
func TestTheRefusalNamesTheAddress(t *testing.T) {
	err := refuseUnsafeAddress("tcp", "169.254.169.254:80", true)
	if err == nil {
		t.Fatal("no error")
	}
	if !strings.Contains(err.Error(), "169.254.169.254") {
		t.Errorf("the refusal does not name the address: %v", err)
	}
}

// TestEveryIdentityProviderResponseBodyIsBounded.
//
// ============================================================================
// One unauthenticated GET took Core's heap to 2.2 GiB.
// ============================================================================
//
// exchangeCode reads its own body through an io.LimitReader, which covers the
// one fetch this package makes itself. The other two — discovery and the JWKS
// refresh — happen inside go-oidc, which uses io.ReadAll, and an *http.Client
// has no setting that bounds a body. A security review measured a 256 MiB
// discovery document from an issuer taking TotalAlloc to 2202 MiB from a single
// anonymous GET of /v1/auth/oidc/start, and returning 200.
//
// The issuer is tenant-administrator configuration, so that is one customer's
// row OOM-killing the process that runs dispatch, ingest and lease renewal for
// every other tenant.
//
// The bound is asserted on the TRANSPORT rather than through a handler, because
// that is where it has to live: below every caller, including ones inside a
// dependency and ones added later.
func TestEveryIdentityProviderResponseBodyIsBounded(t *testing.T) {
	const oversized = MaxIDPResponseBytes * 4

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Streamed rather than allocated, so the test does not itself hold what
		// it is checking Core will not.
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for written := 0; written < oversized; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	// The real client, with the private-address allowance a loopback test server
	// needs — the same setting an on-prem deployment uses.
	client := newOIDCClient(true, nil)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n > MaxIDPResponseBytes {
		t.Errorf("read %d bytes from an identity provider, cap is %d. An unbounded body here is "+
			"an out-of-memory kill of the whole Core process, reachable by one unauthenticated "+
			"GET against a tenant-configured issuer.", n, MaxIDPResponseBytes)
	}
	if n != MaxIDPResponseBytes {
		t.Errorf("read %d bytes, expected the body to be truncated at exactly %d",
			n, MaxIDPResponseBytes)
	}
}

// TestTheBoundedTransportStillClosesTheUnderlyingBody.
//
// The cap replaces what can be READ and keeps the original as the Closer. Get
// that wrong and every fetch leaks a connection, which is a slower version of
// the same outage.
func TestTheBoundedTransportStillClosesTheUnderlyingBody(t *testing.T) {
	var closed bool
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body: &closeRecorder{
				Reader:  bytes.NewReader([]byte("hello")),
				onClose: func() { closed = true },
			},
		}, nil
	})

	b := &boundedBody{max: 1 << 20, inner: inner}
	resp, err := b.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Error("closing the capped body did not close the underlying one; every fetch through " +
			"this client would leak its connection")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeRecorder struct {
	io.Reader
	onClose func()
}

func (c *closeRecorder) Close() error { c.onClose(); return nil }
