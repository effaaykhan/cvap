package domain

import (
	"strings"
	"testing"
	"time"
)

// ADR-096: a same-service SSH host-key contradiction at the held address
// attaches as a KEY ROTATION when every continuity fact holds, and queues as
// ADR-094 says when any one does not. The facts are inputs — correlation
// measures them — and the thresholds are here, where they replay.

func rotationShape() ([]IdentityKey, Candidate) {
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:rotated", "22/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	c := Candidate{AssetID: assetA,
		Keys:        []IdentityKey{key(KeySSHHostKey, "SHA256:before", "22/tcp")},
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}
	return observed, c
}

// allFacts is the data of a genuine rotation at 22/tcp: the new key on two
// scans, the held key last sighted before the first of them, nginx still on
// 443, the family agreeing.
func allFacts() Continuity {
	return Continuity{
		Keys: map[string]KeyContinuity{"22/tcp": {
			NewKeyScans: RotationScans, NewKeyFirstSeen: at.Add(-time.Hour),
			HeldKeySighted: true, HeldKeyLastSeen: at.Add(-2 * time.Hour),
		}},
		HeldServices:     []ServiceSeen{{Port: 443, Protocol: "tcp", Product: "nginx"}},
		ObservedServices: []ServiceSeen{{Port: 443, Protocol: "tcp", Product: "NGINX"}, {Port: 22, Protocol: "tcp", Product: "OpenSSH"}},
		HeldFamily:       "ubuntu", ObservedFamily: "ubuntu",
	}
}

func withKey(f Continuity, mutate func(*KeyContinuity)) Continuity {
	kc := f.Keys["22/tcp"]
	mutate(&kc)
	f.Keys = map[string]KeyContinuity{"22/tcp": kc}
	return f
}

func TestARotationAttachesOnlyWhenEveryContinuityFactHolds(t *testing.T) {
	observed, c := rotationShape()

	// Nothing measured: the ADR-094 handover, queued — and the verdict names
	// the contradicting key so the caller knows what to measure.
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Handover) != 1 || got.Handover[0].Value != "SHA256:rotated" {
		t.Fatalf("unmeasured handover: decision=%v handover=%v (%s); want queue naming the contradicting key",
			got.Decision, got.Handover, got.Reason)
	}

	// Every fact holds: attach, with the contradicting key carried as
	// Rotated and nothing in Contradicted (the caller retires and records).
	f := allFacts()
	c.Continuity = &f
	got = Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionAttach || got.AssetID != assetA {
		t.Fatalf("rotation with every fact: decision=%v (%s), want attach to the asset", got.Decision, got.Reason)
	}
	if len(got.Rotated) != 1 || got.Rotated[0].Value != "SHA256:rotated" || len(got.Contradicted) != 0 {
		t.Fatalf("rotated=%v contradicted=%v; want the new key as Rotated and nothing contradicted", got.Rotated, got.Contradicted)
	}

	// Any single fact short: queued, and the reason names which.
	noProduct := allFacts()
	noProduct.HeldServices = nil
	apache := allFacts()
	apache.ObservedServices = []ServiceSeen{{Port: 443, Protocol: "tcp", Product: "Apache httpd"}}
	silent443 := allFacts()
	silent443.ObservedServices = []ServiceSeen{{Port: 22, Protocol: "tcp", Product: "OpenSSH"}}
	debian := allFacts()
	debian.ObservedFamily = "debian"
	noHint := allFacts()
	noHint.ObservedFamily = ""
	broken := map[string]struct {
		f    Continuity
		want string
	}{
		"one scan only":            {withKey(allFacts(), func(k *KeyContinuity) { k.NewKeyScans = RotationScans - 1 }), "1 scan(s)"},
		"held key seen since":      {withKey(allFacts(), func(k *KeyContinuity) { k.HeldKeyLastSeen = at.Add(-30 * time.Minute) }), "answered since"},
		"held key never sighted":   {withKey(allFacts(), func(k *KeyContinuity) { k.HeldKeySighted = false }), "no sighting on record"},
		"new key live elsewhere":   {withKey(allFacts(), func(k *KeyContinuity) { k.NewKeyHeldElsewhere = true }), "live on another asset"},
		"service not measured":     {Continuity{Keys: map[string]KeyContinuity{}, HeldServices: allFacts().HeldServices, ObservedServices: allFacts().ObservedServices}, "no measurement"},
		"no product on record":     {noProduct, "services not continuous"},
		"a product changed":        {apache, "services not continuous"},
		"a held port went silent":  {silent443, "services not continuous"},
		"the OS family differs":    {debian, "OS family"},
		"no hint against a family": {noHint, "OS family"},
	}
	for name, tc := range broken {
		f := tc.f
		c.Continuity = &f
		got = Resolve(observed, []Candidate{c}, at, window)
		if got.Decision != DecisionQueue || len(got.Rotated) != 0 {
			t.Errorf("%s: decision=%v rotated=%v (%s); want queue", name, got.Decision, got.Rotated, got.Reason)
		}
		if len(got.Handover) != 1 || !strings.Contains(got.Reason, tc.want) {
			t.Errorf("%s: handover=%v reason=%q; a failed classification names the key and the failed fact (%q)", name, got.Handover, got.Reason, tc.want)
		}
	}

	// Data the rules accept without a false negative: a case difference in
	// the product, an extra observed port, an asset with no family.
	lenient := allFacts()
	lenient.HeldFamily = ""
	lenient.ObservedFamily = ""
	c.Continuity = &lenient
	if got = Resolve(observed, []Candidate{c}, at, window); got.Decision != DecisionAttach {
		t.Fatalf("an asset with no family, products matching case-insensitively: decision=%v (%s); want attach", got.Decision, got.Reason)
	}
}

func TestTheHeldKeyAnsweringOnThisScanIsNeverARotation(t *testing.T) {
	// Two keys on one port in one scan — the held key AGREES while the
	// newcomer contradicts — is not a rotation whatever the history says.
	f := allFacts()
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:rotated", "22/tcp"),
		key(KeySSHHostKey, "SHA256:before", "22/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	c := Candidate{AssetID: assetA,
		Keys:        []IdentityKey{key(KeySSHHostKey, "SHA256:before", "22/tcp")},
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute), Continuity: &f}
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Rotated) != 0 || !strings.Contains(got.Reason, "two different keys answered on 22/tcp") {
		t.Fatalf("held key answering on this scan: decision=%v rotated=%v (%s); want queue naming two keys on one port", got.Decision, got.Rotated, got.Reason)
	}
	// The same refusal one layer down, for a caller that measured
	// continuity for a key the held key agrees with from another source
	// shape: rotationFailures itself names an agreeing same-service key.
	if why := rotationFailures(
		[]IdentityKey{key(KeySSHHostKey, "SHA256:rotated", "22/tcp")},
		[]IdentityKey{key(KeySSHHostKey, "SHA256:before", "22/tcp")}, &f); len(why) == 0 || !strings.Contains(strings.Join(why, ";"), "answered on this scan") {
		t.Fatalf("rotationFailures with the held key agreeing on the same service = %v; want a refusal naming it", why)
	}
}

func TestTwoKeysContradictingOnOnePortAreNeverARotation(t *testing.T) {
	// Two different newcomer keys on 22 in one scan: the measurement is per
	// service, so both would be judged on one key's two-scan history — and
	// the apply loop would retire the first one it recorded. Refused.
	f := allFacts()
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:fresh", "22/tcp"),
		key(KeySSHHostKey, "SHA256:established", "22/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	c := Candidate{AssetID: assetA,
		Keys:        []IdentityKey{key(KeySSHHostKey, "SHA256:before", "22/tcp")},
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute), Continuity: &f}
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Rotated) != 0 || !strings.Contains(got.Reason, "two different keys answered on 22/tcp") {
		t.Fatalf("two contradicting keys on one port: decision=%v rotated=%v (%s); want queue naming it", got.Decision, got.Rotated, got.Reason)
	}
	if len(got.Candidates) != 1 || got.Candidates[0] != assetA {
		t.Errorf("candidates = %v; want the address holder offered", got.Candidates)
	}

	// At an address NOTHING holds: still queued, with no candidate — an
	// "unplaceable" item, never one asset holding two hosts' keys (the
	// review measured that asset contradicting itself for ever).
	got = Resolve(observed, nil, at, window)
	if got.Decision != DecisionQueue || len(got.Candidates) != 0 {
		t.Fatalf("two keys on one port at a free address: decision=%v candidates=%v (%s); want queue with no candidate",
			got.Decision, got.Candidates, got.Reason)
	}
}

func TestARotationClassifiesOnlyAnSSHHostKey(t *testing.T) {
	// A contradiction of another moderate type from the same service, with
	// every fact MEASURED for that service and holding: banner continuity
	// forgives nothing but an SSH key. (The measurement is keyed by the
	// conflict's source on purpose — without it the type check would be
	// shadowed by "no measurement" and this test would prove nothing.)
	f := allFacts()
	observed := []IdentityKey{
		key(KeyHostnameOS, "web-1.example|ubuntu", "22/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	c := Candidate{AssetID: assetA,
		Keys:        []IdentityKey{key(KeyHostnameOS, "db-9.example|debian", "22/tcp")},
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute), Continuity: &f}
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Rotated) != 0 {
		t.Fatalf("non-SSH contradiction with every fact: decision=%v rotated=%v (%s); want queue", got.Decision, got.Rotated, got.Reason)
	}
}

func TestARotationBesideASteadyCertificateAttachesWithTheCertificateCorroborating(t *testing.T) {
	// `ssh-keygen -A` on a TLS host: the SSH key contradicts, the certificate
	// agrees. Without facts this is the not-outvoted guard (queue); with them
	// it is a rotation, and the agreeing certificate is the corroboration.
	f := allFacts()
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:rotated", "22/tcp"),
		key(KeyServiceCert, "SHA256:steady", "443/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	held := []IdentityKey{
		key(KeySSHHostKey, "SHA256:before", "22/tcp"),
		key(KeyServiceCert, "SHA256:steady", "443/tcp"),
	}
	c := Candidate{AssetID: assetA, Keys: held, HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Handover) != 1 {
		t.Fatalf("unmeasured: decision=%v handover=%v; want queue naming the SSH key", got.Decision, got.Handover)
	}
	c.Continuity = &f
	got = Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionAttach || len(got.Rotated) != 1 || got.Rotated[0].Type != KeySSHHostKey {
		t.Fatalf("measured: decision=%v rotated=%v (%s); want attach rotating the SSH key", got.Decision, got.Rotated, got.Reason)
	}
	if len(got.Corroborated) != 1 || got.Corroborated[0].Value != "SHA256:steady" {
		t.Errorf("corroborated=%v; want the steady certificate", got.Corroborated)
	}

	// A reimage renews the certificate too: the SSH key is Rotated, the
	// certificate stays Contradicted — under the establishment gate, because
	// the facts measured nothing about it — and nothing corroborates it.
	observed[1] = key(KeyServiceCert, "SHA256:renewed", "443/tcp")
	got = Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionAttach || len(got.Rotated) != 1 || len(got.Contradicted) != 1 || len(got.Corroborated) != 0 {
		t.Fatalf("reimage: decision=%v rotated=%v contradicted=%v corroborated=%v; want the SSH key Rotated, "+
			"the certificate Contradicted and uncorroborated", got.Decision, got.Rotated, got.Contradicted, got.Corroborated)
	}
}

func TestAWeakOnlySightingAtAContestedAddressWaits(t *testing.T) {
	// The address alone, at an address with a pending contradiction naming
	// the asset: it waits with the contradiction rather than attaching — the
	// batch-overflow door (ADR-096 step 1).
	observed := []IdentityKey{key(KeyIPWindow, "10.10.0.11", "net")}
	c := Candidate{AssetID: assetA,
		Keys:        []IdentityKey{key(KeySSHHostKey, "SHA256:occupant", "22/tcp")},
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute),
		PendingContested: true, ContradictionLastSeen: at.Add(-time.Hour)}
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Candidates) != 1 || got.Candidates[0] != assetA || len(got.Handover) != 0 {
		t.Fatalf("weak-only at a contested address: decision=%v candidates=%v handover=%v (%s); want queue, no handover to measure",
			got.Decision, got.Candidates, got.Handover, got.Reason)
	}

	// The occupant's own key agreeing: waits too. A fingerprint is a public
	// value and the probe verifies no possession, so at a contested address
	// one agreement is not evidence — the review defeated the weak-only park
	// by echoing the occupant's certificate beside the newcomer's services.
	withKey := append([]IdentityKey{key(KeySSHHostKey, "SHA256:occupant", "22/tcp")}, observed...)
	got = Resolve(withKey, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue || len(got.Handover) != 0 {
		t.Fatalf("occupant's key at its contested address: decision=%v handover=%v (%s); want queue — the address is contested for everyone", got.Decision, got.Handover, got.Reason)
	}

	// A MERGE-grade agreement — two independent moderate keys — proceeds:
	// that is ADR-007's bar, and B40's exposure, unchanged here.
	c.Keys = append(c.Keys, key(KeyServiceCert, "SHA256:occupantcert", "443/tcp"))
	merge := append([]IdentityKey{key(KeyServiceCert, "SHA256:occupantcert", "443/tcp")}, withKey...)
	got = Resolve(merge, []Candidate{c}, at, window)
	if got.Decision != DecisionMerge {
		t.Fatalf("merge-grade agreement at a contested address: decision=%v (%s); want merge", got.Decision, got.Reason)
	}
	c.Keys = c.Keys[:1]

	// A STALE contest — items pending, but no contradicting key seen for a
	// full window — no longer parks: the occupant's sighting attaches and
	// the caller expires the items. A park with no expiry was measured as a
	// detection denial of service with a one-packet trigger.
	c.ContradictionLastSeen = at.Add(-window - time.Minute)
	got = Resolve(withKey, []Candidate{c}, at, window)
	if got.Decision != DecisionAttach {
		t.Fatalf("stale contest: decision=%v (%s); want attach", got.Decision, got.Reason)
	}
	c.ContradictionLastSeen = at.Add(-time.Hour)

	// Nothing pending: the weak-only attach ADR-007 allows.
	c.PendingContested = false
	c.ContradictionLastSeen = time.Time{}
	got = Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionAttach {
		t.Fatalf("weak-only, nothing pending: decision=%v (%s); want attach", got.Decision, got.Reason)
	}
}

func TestALapsedOccupantMakesTheNewcomerANewAsset(t *testing.T) {
	// A bare handover whose occupant's key has not answered here for a full
	// window while the newcomer answered on two scans: ADR-094's aged-out
	// address with the contest as witness — a new asset for the newcomer,
	// the occupant named as Lapsed. Measured without it: a genuine host on a
	// reused lease parked for ever, the gone occupant's products never
	// continuous again.
	observed, c := rotationShape()
	f := allFacts()
	f = withKey(f, func(k *KeyContinuity) { k.HeldKeyLastSeen = at.Add(-window - time.Hour) })
	f.HeldServices = nil // the occupant's products have aged out too
	c.Continuity = &f
	// The newcomer's parks keep the contest fresh: that is what holds the
	// address for the decision once the interval has aged (step 1 §3).
	c.PendingContested, c.ContradictionLastSeen = true, at.Add(-time.Hour)
	// The occupant's INTERVAL is inside the window (it attached a minute
	// ago, keyless sightings): not lapsed, whatever its key's sighting says
	// — the review measured a live host evicted in three scans of tcp/22
	// and the attacker's key trusted at the second.
	got := Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionQueue {
		t.Fatalf("occupant attached inside the window: decision=%v (%s); want queue — a live occupant has not lapsed", got.Decision, got.Reason)
	}
	c.AddressLastSeen = at.Add(-window - time.Hour)
	got = Resolve(observed, []Candidate{c}, at, window)
	if got.Decision != DecisionNewAsset || got.Lapsed != assetA {
		t.Fatalf("lapsed occupant: decision=%v lapsed=%v (%s); want a new asset naming the lapsed holder", got.Decision, got.Lapsed, got.Reason)
	}
	// Not lapsed while the occupant answered inside the window, or the
	// newcomer has only one scan, or the held key has no sighting here, or
	// something of the occupant still agrees.
	for name, tc := range map[string]func(){
		"held key answered inside the window": func() { f = withKey(f, func(k *KeyContinuity) { k.HeldKeyLastSeen = at.Add(-time.Hour) }) },
		"newcomer on one scan only":           func() { f = withKey(f, func(k *KeyContinuity) { k.NewKeyScans = 1 }) },
		"held key never sighted here":         func() { f = withKey(f, func(k *KeyContinuity) { k.HeldKeySighted = false }) },
		"newcomer key live on another asset":  func() { f = withKey(f, func(k *KeyContinuity) { k.NewKeyHeldElsewhere = true }) },
	} {
		f = allFacts()
		f = withKey(f, func(k *KeyContinuity) { k.HeldKeyLastSeen = at.Add(-window - time.Hour) })
		tc()
		c.Continuity = &f
		if got = Resolve(observed, []Candidate{c}, at, window); got.Decision != DecisionQueue {
			t.Errorf("%s: decision=%v (%s); want queue", name, got.Decision, got.Reason)
		}
	}
	f = allFacts()
	f = withKey(f, func(k *KeyContinuity) { k.HeldKeyLastSeen = at.Add(-window - time.Hour) })
	c.Continuity = &f
	c.Keys = append(c.Keys, key(KeyServiceCert, "SHA256:steady", "443/tcp"))
	withCert := append([]IdentityKey{key(KeyServiceCert, "SHA256:steady", "443/tcp")}, observed...)
	if got = Resolve(withCert, []Candidate{c}, at, window); got.Decision == DecisionNewAsset {
		t.Fatalf("occupant's certificate still agreeing: decision=%v (%s); a lapse needs nothing of the occupant answering", got.Decision, got.Reason)
	}
	c.Keys = c.Keys[:1]

	// Scored, not returned: a mover whose keys ANOTHER asset holds at merge
	// grade is that asset's, and the lapsed holder is evicted by the merge,
	// not duplicated by a new keyless asset (measured).
	mover := Candidate{AssetID: assetB, Keys: []IdentityKey{
		key(KeySSHHostKey, "SHA256:rotated", "22/tcp"), key(KeyServiceCert, "SHA256:movercert", "443/tcp")}}
	moving := append([]IdentityKey{key(KeyServiceCert, "SHA256:movercert", "443/tcp")}, observed...)
	got = Resolve(moving, []Candidate{c, mover}, at, window)
	if got.Decision != DecisionMerge || got.AssetID != assetB {
		t.Fatalf("mover held elsewhere at merge grade beside a lapsed occupant: decision=%v asset=%v (%s); want the merge", got.Decision, got.AssetID, got.Reason)
	}
}

func TestAPendingItemExtendsTheHoldOnAnAgedAddress(t *testing.T) {
	// The occupant was last ATTACHED at the address before the window — a
	// park touches no interval — but an item is pending there. The address
	// is still the occupant's for the decision: a newcomer's contradiction
	// is a handover (queued), not a new asset, and the occupant's own return
	// is judged against its own asset. Measured: without this, seven days of
	// waiting made the newcomer a new asset with a trusted key.
	aged := Candidate{AssetID: assetA,
		Keys:        []IdentityKey{key(KeySSHHostKey, "SHA256:occupant", "22/tcp")},
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-window - 24*time.Hour),
		PendingContested: true, ContradictionLastSeen: at.Add(-time.Hour)}
	newcomer := []IdentityKey{key(KeySSHHostKey, "SHA256:newcomer", "22/tcp"), key(KeyIPWindow, "10.10.0.11", "net")}
	got := Resolve(newcomer, []Candidate{aged}, at, window)
	if got.Decision != DecisionQueue || len(got.Handover) != 1 {
		t.Fatalf("newcomer at an aged, contested address: decision=%v handover=%v (%s); want the handover queued, not a new asset",
			got.Decision, got.Handover, got.Reason)
	}
	// The same shape with the contest STALE (pending, but no contradiction
	// inside the window) or with nothing pending is ADR-094's aged-out
	// address: a new asset, as before — an unbounded hold was measured
	// keeping a dead occupant's address for ever.
	aged.ContradictionLastSeen = at.Add(-window - time.Hour)
	got = Resolve(newcomer, []Candidate{aged}, at, window)
	if got.Decision != DecisionNewAsset {
		t.Fatalf("newcomer at an aged address with a stale contest: decision=%v (%s); want a new asset (ADR-094)", got.Decision, got.Reason)
	}
	aged.PendingContested, aged.ContradictionLastSeen = false, time.Time{}
	got = Resolve(newcomer, []Candidate{aged}, at, window)
	if got.Decision != DecisionNewAsset {
		t.Fatalf("newcomer at an aged, uncontested address: decision=%v (%s); want a new asset (ADR-094)", got.Decision, got.Reason)
	}
}
