package correlate

import (
	"encoding/json"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// The credentialed release-precedence rule (ADR-076/077) is DORMANT: no scan point
// emits `package` observations today, so credentialedRelease returns false on every
// real host and the band vote decides. These tests exercise the decision in
// isolation, so the rule is verified now — while the measurement motivating it is in
// front of us — and fires correctly the day the deferred production engine emits.

func pkgObs(payload any) store.Observation {
	b, _ := json.Marshal(payload)
	return store.Observation{Type: store.ObsPackage, Payload: b}
}

func TestCredentialedReleaseOutranksWhenPresent(t *testing.T) {
	h := host{obs: []store.Observation{
		{Type: store.ObsService, Payload: []byte(`{"product":"OpenSSH","version":"8.9"}`)}, // a band voter
		pkgObs(packagePayload{Address: "10.0.0.9", Release: "jammy", ReleaseSource: "os-release"}),
	}}
	rel, ok := credentialedRelease(h)
	if !ok || rel != "jammy" {
		t.Fatalf("credentialedRelease = (%q, %v), want (jammy, true)", rel, ok)
	}
}

func TestCredentialedReleaseAbsentWithoutPackageObs(t *testing.T) {
	// The real-host case today: only band-vote inputs, no `package` observation.
	h := host{obs: []store.Observation{
		{Type: store.ObsService, Payload: []byte(`{"product":"OpenSSH","version":"8.9"}`)},
	}}
	if rel, ok := credentialedRelease(h); ok {
		t.Errorf("credentialedRelease = (%q, true) with no package obs; want dormant (false)", rel)
	}
}

func TestCredentialedReleaseIgnoresNonAuthoritativeSource(t *testing.T) {
	// A `package` observation whose release was not read from /etc/os-release must
	// NOT outrank the vote — only an exact, read release is ground truth.
	h := host{obs: []store.Observation{
		pkgObs(packagePayload{Address: "10.0.0.9", Release: "jammy", ReleaseSource: "inferred"}),
		pkgObs(packagePayload{Address: "10.0.0.9", Release: "", ReleaseSource: "os-release"}), // empty release
	}}
	if rel, ok := credentialedRelease(h); ok {
		t.Errorf("credentialedRelease = (%q, true) for non-authoritative/empty; want false", rel)
	}
}
