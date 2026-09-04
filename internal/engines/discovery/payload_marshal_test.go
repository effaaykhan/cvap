package discovery

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The RETURN path, which had no test.
//
// ============================================================================
// A field dropped on the way OUT costs coverage. A field dropped on the way
// BACK loses evidence already gathered and already paid for in packets.
// ============================================================================
//
// `enginewire.Probe.Kind` was dropped in translation and nothing noticed: both
// sides compiled and the receiver saw a zero value. Every observation payload
// has the same exposure in the other direction — a field without a JSON tag, one
// marked `json:"-"`, one left unexported — and the failure is silent in exactly
// the same way, except that the packets have already been sent.
//
// The counterpart of this file lives in internal/engines/fingerprint.

// assertEveryFieldReachesTheJSON marshals a payload and requires every exported
// field to appear.
//
// The fixture must set every field non-zero, and the test FAILS if it does not:
// a fixture that leaves a field zero passes over exactly the field that was
// forgotten.
func assertEveryFieldReachesTheJSON(t *testing.T, name string, v any) {
	t.Helper()

	rv := reflect.ValueOf(v)
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%s: marshalled to something that is not an object: %v", name, err)
	}

	for i := range rv.NumField() {
		f := rv.Type().Field(i)
		if !f.IsExported() {
			t.Errorf("%s.%s is unexported and therefore cannot travel", name, f.Name)
			continue
		}
		if rv.Field(i).IsZero() {
			t.Errorf("%s.%s is zero in this fixture, so it is not checked. Set it.", name, f.Name)
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			t.Errorf("%s.%s is tagged json:\"-\" and is silently discarded", name, f.Name)
			continue
		}
		key, _, _ := strings.Cut(tag, ",")
		if key == "" {
			key = f.Name
		}
		if _, ok := got[key]; !ok {
			t.Errorf("%s.%s does not reach the JSON as %q", name, f.Name, key)
		}
	}
}

// TestEveryHostPayloadFieldReachesTheWire.
//
// PortsScanned is the one that matters most: it is the coverage record, and
// "no open ports" is ambiguous without it — a host that was scanned and had
// none looks identical to one that was never reached.
func TestEveryHostPayloadFieldReachesTheWire(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "hostPayload", hostPayload{
		Address: "10.10.0.11", Alive: true, Method: "tcp", Detail: "a reason",
		SafetyMode: "safe", PortsScanned: []uint16{22, 80}, PortsOpen: 2,
	})
}

// TestEveryPortPayloadFieldReachesTheWire.
func TestEveryPortPayloadFieldReachesTheWire(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "portPayload", portPayload{
		Address: "10.10.0.11", Port: 22, Protocol: "tcp", State: "open",
		SafetyMode: "safe",
	})
}

// TestEveryBannerPayloadFieldReachesTheWire.
//
// Solicited is the field an operator reads when asked whether we touched a host,
// and Probe is what a claim is traced back to. Both are provenance, and
// provenance that does not travel is provenance nobody has.
func TestEveryBannerPayloadFieldReachesTheWire(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "bannerPayload", bannerPayload{
		Address: "10.10.0.11", Port: 22, Data: []byte("SSH-2.0-OpenSSH_10.3"),
		Solicited: true, Probe: "newline", SafetyMode: "intrusive",
	})
}
