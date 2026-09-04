package fingerprint

import (
	"encoding/json"
	"testing"
)

// The one field in the service payload that is a CONTROL rather than a value.
//
// Mutations, declared beside the tests that must kill them.
//
// The declarations live in their own file because a suite carries ONE
// mutate:test line: a second one in the same file silently overrides the first,
// and five mutations against tls.go were reported as surviving when they had
// only ever been run against this test. `make mutate` caught it, which is the
// argument for running the gate before pushing rather than after.

// TestAnOSHintIsNeverAuthoritative.
//
// Mechanical, not documentary. The struct has no field to set, so there is no
// assignment anywhere — present or future — that can make an OS hint claim
// authority. ADR-014 makes OS attribution decide which vendor advisory feed a
// host is matched against, and a wrong feed at high confidence poisons the
// knowledge plane rather than merely this scan.
//
// mutate:subject internal/engines/fingerprint/payload.go
// mutate:test    ./internal/engines/fingerprint/ -run TestAnOSHintIsNeverAuthoritative
//
// mutate:case    an OS hint is emitted as authoritative
// mutate:old     }{Hint: o.Hint, Source: o.Source, Authoritative: false})
// mutate:new     }{Hint: o.Hint, Source: o.Source, Authoritative: true})
func TestAnOSHintIsNeverAuthoritative(t *testing.T) {
	b, err := json.Marshal(osHint{Hint: "Ubuntu", Source: "service banner"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["authoritative"] != false {
		t.Errorf("authoritative = %v, want false; an OS hint is a string the host chose to send",
			got["authoritative"])
	}

	// And through the whole payload, which is the shape that actually travels.
	p := servicePayload{Service: "ssh", OS: &osHint{Hint: "Debian", Source: "service banner"}}
	full, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		OS struct {
			Hint          string `json:"hint"`
			Authoritative bool   `json:"authoritative"`
		} `json:"os"`
	}
	if err := json.Unmarshal(full, &back); err != nil {
		t.Fatal(err)
	}
	if back.OS.Hint != "Debian" || back.OS.Authoritative {
		t.Errorf("os = %+v, want the hint carried and authoritative false", back.OS)
	}
}

// TestABannerOSHintReachesTheObservation.
//
// The hint is worth carrying — an OpenSSH banner naming a distribution is
// genuinely the input ADR-014 wants for advisory matching. It travels; it just
// never travels as authority.
func TestABannerOSHintReachesTheObservation(t *testing.T) {
	s := serveGreeting(t, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
	cfg := baseConfig(s.port)
	cfg.BannerMatches = []Match{{
		Pattern: `^SSH-2\.0-OpenSSH_(?P<version>[0-9][\w.]*)[ -]+(?P<info>[Uu]buntu\S*)`,
		Service: "ssh", Product: "OpenSSH", OSHint: "Ubuntu", Confidence: 0.95,
	}}

	got := collect(t, cfg, target())
	if len(got) != 1 || got[0].OS == nil {
		t.Fatalf("no OS hint reached the observation: %+v", got)
	}
	if got[0].OS.Hint != "Ubuntu" {
		t.Errorf("hint = %q", got[0].OS.Hint)
	}
	if got[0].Info != "Ubuntu-3ubuntu0.4" {
		t.Errorf("info = %q, want the vendor package string", got[0].Info)
	}
}
