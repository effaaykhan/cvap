package correlate

import (
	"encoding/json"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// One spelling per address (ADR-096): a non-canonical spelling grouped apart
// from the canonical one and routed around every by-address control — the
// review measured "10.77.6.010", an unabbreviated IPv6 and a "/24" suffix
// each ageing the occupant out of its address. netip is strict and renders
// one form; what it refuses is left unresolved.
// One grammar for the protocol on the identity path: absent or "tcp" (any
// case) is tcp and anything else lifts no key — the one-live-key-per-service
// index mirrors the key's Source, a spelling the index refused was measured
// retrying the group for ever, and a non-tcp claim was measured reaching the
// tcp key's trust row.
func TestKeysFromNormalisesTheProtocolOrLiftsNoKey(t *testing.T) {
	obs := func(proto string) store.Observation {
		m := map[string]any{"address": "10.44.3.10", "port": 22, "service": "ssh",
			"ssh": map[string]any{"fingerprint": "SHA256:abc"}}
		if proto != "-" {
			m["protocol"] = proto
		}
		b, _ := json.Marshal(m)
		return store.Observation{Type: store.ObsService, Payload: b}
	}
	// tcp only until the sightings carry a protocol (B45): a udp claim on
	// port 22 was measured landing in the tcp key's sighting row.
	for proto, want := range map[string]string{"-": "22/tcp", "": "22/tcp", "TCP": "22/tcp", "Udp": "", "sctp": "", "quic": "", "tcp ": "22/tcp"} {
		keys := keysFrom(obs(proto), "10.44.3.10")
		got := ""
		if len(keys) > 0 {
			got = keys[0].Source
		}
		if got != want {
			t.Errorf("protocol %q: source %q, want %q", proto, got, want)
		}
	}
}

func TestGroupByAddressCanonicalisesOrRefuses(t *testing.T) {
	obs := func(addr string) store.Observation {
		b, _ := json.Marshal(map[string]any{"address": addr, "port": 22})
		return store.Observation{Type: store.ObsService, Payload: b}
	}
	hosts := groupByAddress([]store.Observation{
		obs("2001:0db8:0077:0000:0000:0000:0000:0020"),
		obs("2001:db8:77::20"),
		obs("::ffff:10.44.3.10"),
		obs("10.44.3.10"),
		obs("10.77.6.010"),   // leading zero: refused
		obs("10.44.3.10/24"), // a mask: refused
		obs("fe80::1%eth0"),  // a zone: netip accepts it, inet does not — refused
		obs("not-an-address"),
	})
	got := map[string]int{}
	for _, h := range hosts {
		got[h.address] = len(h.obs)
	}
	want := map[string]int{"2001:db8:77::20": 2, "10.44.3.10": 2}
	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v: every spelling of one address is one group, and the refused ones none", got, want)
	}
	for a, n := range want {
		if got[a] != n {
			t.Errorf("group %q has %d observations, want %d", a, got[a], n)
		}
	}
}
