package correlate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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

// Core's site of the release token grammar (ADR-095): a `package` observation
// whose family or release is outside [a-z0-9._-]{1,64} is not an attribution,
// whatever build of the engine sent it — it falls through to band voting exactly
// as a payload with no family does.
func TestCredentialedAttributionRefusesTokensOutsideTheGrammar(t *testing.T) {
	for name, payload := range map[string]string{
		"html in family":  `{"address":"10.0.0.1","family":"ubuntu<script>","release":"noble","release_source":"os-release","installed":[]}`,
		"path in release": `{"address":"10.0.0.1","family":"ubuntu","release":"../../etc/passwd","release_source":"os-release","installed":[]}`,
		"uppercase":       `{"address":"10.0.0.1","family":"Ubuntu","release":"noble","release_source":"os-release","installed":[]}`,
		"too long":        `{"address":"10.0.0.1","family":"ubuntu","release":"` + strings.Repeat("a", 65) + `","release_source":"os-release","installed":[]}`,
	} {
		h := host{obs: []store.Observation{{Type: store.ObsPackage, Payload: []byte(payload), ObservedAt: time.Now()}}}
		if _, ok := credentialedAttribution(h); ok {
			t.Errorf("%s: a token outside the grammar was accepted as an exact attribution", name)
		}
	}
	good := host{obs: []store.Observation{{Type: store.ObsPackage, ObservedAt: time.Now(),
		Payload: []byte(`{"address":"10.0.0.1","family":"ubuntu","release":"noble","release_source":"os-release","installed":[]}`)}}}
	if _, ok := credentialedAttribution(good); !ok {
		t.Fatal("a well-formed exact attribution was refused")
	}
}
