package correlate

import (
	"encoding/json"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// The credentialed release-precedence rule (ADR-076/077/089): an exact family+release
// read from /etc/os-release outranks the service-inferred family and the band-vote
// release. ADR-089 moved this ahead of the `family != ""` gate so a package-only
// sweep reaches it — these tests pin the read-side decision: it fires only on an
// exact, authoritative read that carries a family, and falls through otherwise.

func pkgObs(payload any) store.Observation {
	b, _ := json.Marshal(payload)
	return store.Observation{Type: store.ObsPackage, Payload: b}
}

func TestCredentialedAttributionOutranksWhenPresent(t *testing.T) {
	h := host{obs: []store.Observation{
		{Type: store.ObsService, Payload: []byte(`{"product":"OpenSSH","version":"8.9"}`)}, // a band voter
		pkgObs(packagePayload{Address: "10.0.0.9", Family: "ubuntu", Release: "jammy", ReleaseSource: "os-release"}),
	}}
	f, ok := credentialedAttribution(h)
	if !ok || f.Release != "jammy" || f.Family != "ubuntu" {
		t.Fatalf("credentialedAttribution = (%+v, %v), want ({ubuntu jammy}, true)", f, ok)
	}
}

func TestCredentialedAttributionAbsentWithoutPackageObs(t *testing.T) {
	// Only band-vote inputs, no `package` observation: band voting decides.
	h := host{obs: []store.Observation{
		{Type: store.ObsService, Payload: []byte(`{"product":"OpenSSH","version":"8.9"}`)},
	}}
	if f, ok := credentialedAttribution(h); ok {
		t.Errorf("credentialedAttribution = (%+v, true) with no package obs; want false", f)
	}
}

func TestCredentialedAttributionIgnoresNonAuthoritativeSource(t *testing.T) {
	// A `package` observation whose release was not read from /etc/os-release, or that
	// carries no family, must NOT outrank the vote — only an exact, read release with
	// a ground-truth family is self-sufficient attribution (ADR-089).
	h := host{obs: []store.Observation{
		pkgObs(packagePayload{Address: "10.0.0.9", Family: "ubuntu", Release: "jammy", ReleaseSource: "inferred"}),
		pkgObs(packagePayload{Address: "10.0.0.9", Family: "ubuntu", Release: "", ReleaseSource: "os-release"}), // empty release
		pkgObs(packagePayload{Address: "10.0.0.9", Family: "", Release: "jammy", ReleaseSource: "os-release"}),  // no family
	}}
	if f, ok := credentialedAttribution(h); ok {
		t.Errorf("credentialedAttribution = (%+v, true) for non-authoritative/empty/family-less; want false", f)
	}
}
