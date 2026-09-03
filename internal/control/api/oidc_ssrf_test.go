package api

import (
	"strings"
	"testing"
)

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

// TestTheGuardIsAnAllowlistNotABlocklist.
//
// Every range below is one a blocklist typically forgets, and each is refused
// because the structure is "permit public unicast, refuse the rest" rather than
// a list of bad prefixes.
func TestTheGuardIsAnAllowlistNotABlocklist(t *testing.T) {
	for _, tc := range []struct{ addr, why string }{
		{"100.64.0.1:443", "RFC 6598 carrier-grade NAT, where cloud infrastructure often sits"},
		{"0.0.0.0:443", "the unspecified address"},
		{"[::]:443", "the IPv6 unspecified address"},
		{"224.0.0.1:443", "multicast"},
		{"[ff02::1]:443", "IPv6 multicast"},
		{"[2001:0:1:2:3:4:5:6]:443", "Teredo, which carries an embedded v4 address"},
	} {
		if err := refuseUnsafeAddress("tcp", tc.addr, true); err == nil {
			t.Errorf("%s was permitted even with allowPrivate; it is %s", tc.addr, tc.why)
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
