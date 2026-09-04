package fingerprint

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The RETURN path, which had no test and is the more expensive one to get wrong.
//
// ============================================================================
// A field dropped on the way OUT costs coverage. A field dropped on the way
// BACK loses evidence already gathered and already paid for in packets.
// ============================================================================
//
// `enginewire.Probe.Kind` was dropped in translation and nothing noticed: both
// sides compiled and the receiver saw a zero value. Every observation payload
// this engine emits has the same exposure in the other direction — a field
// without a JSON tag, a field marked `json:"-"`, a field left unexported by
// accident — and the failure is silent in exactly the same way.
//
// It is worse here because the packets have already been sent. An SSH host key
// that reaches the payload struct and not the JSON is an identity key bought at
// the cost of a key exchange and then thrown away, and the observation looks
// complete.

// assertEveryFieldReachesTheJSON marshals a payload and requires every exported
// field of it to appear.
//
// The fixture must set every field to something non-zero, and the test FAILS if
// it does not — a fixture that leaves a field zero passes over exactly the field
// that was forgotten, which is the failure this whole test exists to catch.
func assertEveryFieldReachesTheJSON(t *testing.T, name string, v any) {
	t.Helper()

	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			t.Fatalf("%s: fixture is nil", name)
		}
		rv = rv.Elem()
	}

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
			// An unexported field cannot be marshalled at all. Named rather than
			// skipped: if a payload grows one, that is the bug.
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
			t.Errorf("%s.%s does not reach the JSON as %q; the evidence is gathered and "+
				"then dropped on the way out", name, f.Name, key)
		}
	}
}

// TestEveryServicePayloadFieldReachesTheWire.
func TestEveryServicePayloadFieldReachesTheWire(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "servicePayload", servicePayload{
		Address: "10.10.0.14", Port: 22, Protocol: "tcp",
		Service: "ssh", Product: "OpenSSH", Version: "10.3", Info: "Ubuntu-3",
		Softmatch: true, Method: "banner", Solicited: true, SafetyMode: "intrusive",
		Probe: "ssh-hostkey", Pattern: "^SSH-", Evidence: "SSH-2.0-OpenSSH_10.3",
		Detail: "a refusal reason",
		OS:     &osHint{Hint: "Ubuntu", Source: "service banner"},
		TLS:    &tlsPayload{Version: "TLSv1.3"},
		SSH:    &sshPayload{Fingerprint: "SHA256:x"},
	})
}

// TestEveryTLSPayloadFieldReachesTheWire.
//
// This is the object week 6's certificate rules read. A field that does not
// arrive is a rule that cannot be written.
func TestEveryTLSPayloadFieldReachesTheWire(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "tlsPayload", tlsPayload{
		Version: "TLSv1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ALPN: "h2",
		Chain:       []certPayload{{Fingerprint: "SHA256:x"}},
		ChainLength: 3, ChainTruncated: true,
	})

	assertEveryFieldReachesTheJSON(t, "certPayload", certPayload{
		Fingerprint: "SHA256:abc",
		Subject:     "CN=a", Issuer: "CN=b", Serial: "42",
		NotBefore: time.Now().UTC().Format(time.RFC3339),
		NotAfter:  time.Now().UTC().Format(time.RFC3339),
		DNSNames:  []string{"a.invalid"}, IPAddresses: []string{"10.10.0.15"},
		NamesTruncated: true, SelfSigned: true, IsCA: true,
		SignatureAlgorithm: "SHA256-RSA", PublicKeyAlgorithm: "RSA", KeyBits: 2048,
		ExtensionCount: 204, ExtensionsUnusual: true,
	})
}

// TestEverySSHPayloadFieldReachesTheWire.
//
// The fingerprint here is ADR-007's `ssh_hostkey`, bought with a key exchange.
// Losing it in translation would mean paying for an identity key and discarding
// it, with the observation looking complete.
func TestEverySSHPayloadFieldReachesTheWire(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "sshPayload", sshPayload{
		HostKeyType: "ssh-ed25519", Fingerprint: "SHA256:abc",
		HostKeyAlgorithms: []string{"ssh-ed25519"}, KexAlgorithms: []string{"curve25519-sha256"},
		Truncated: true,
	})
}

// TestTheOSHintMarshalsBothItsFieldsAndTheFlag.
//
// osHint has a hand-written MarshalJSON, which is the shape most likely to lose
// a field when one is added: the reflection above sees the struct and the method
// writes an anonymous one, and nothing connects them.
func TestTheOSHintMarshalsBothItsFieldsAndTheFlag(t *testing.T) {
	assertEveryFieldReachesTheJSON(t, "osHint", osHint{Hint: "Ubuntu", Source: "service banner"})

	raw, err := json.Marshal(osHint{Hint: "Ubuntu", Source: "service banner"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["authoritative"]; !ok {
		t.Error("the authoritative flag does not reach the JSON; it is a control and its " +
			"absence reads as unset rather than false")
	}
}

// TestAServiceObservationSurvivesTheWireRoundTrip.
//
// The generic checks above are about struct tags. This is about the whole path:
// what the engine actually emitted, marshalled the way the process shell sends
// it, decoded the way the runtime receives it, with the two identity keys still
// present. Those are the fields a resolver cannot work without.
func TestAServiceObservationSurvivesTheWireRoundTrip(t *testing.T) {
	srv := newSSHServer(t, &sshServer{})

	cfg := baseConfig(srv.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{Name: "ssh-hostkey", Kind: probeKindSSHHostKey, Ports: []uint16{srv.port}}}

	var payloads [][]byte
	emit := func(o Observation) error {
		payloads = append(payloads, o.Payload)
		return nil
	}
	if err := Run(t.Context(), cfg, target(), emit, func(uint32) {}); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("emitted %d observations, want 1", len(payloads))
	}

	var back servicePayload
	if err := json.Unmarshal(payloads[0], &back); err != nil {
		t.Fatalf("the payload does not decode into the type that produced it: %v", err)
	}
	if back.SSH == nil || back.SSH.Fingerprint == "" {
		t.Fatal("the SSH host key did not survive; a key exchange was paid for and discarded")
	}
	if back.Service != "ssh" || !back.Solicited {
		t.Errorf("service=%q solicited=%v after the round trip", back.Service, back.Solicited)
	}
}
