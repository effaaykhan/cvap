package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// The merge rule, case by case.
//
// ============================================================================
// A wrong merge is the one decision in this system that cannot be undone by
// looking again.
// ============================================================================
//
// It interleaves two hosts' findings, exposures and timelines, and afterwards
// nobody can tell which is which (ADR-007). So these tests are about the cases
// that must NOT merge at least as much as the ones that must.
//
// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/domain/identity.go
// mutate:test    ./internal/domain/ -run TestOneStrongKey|TestTwoModerate|TestAModerateAnd|TestWeakEvidence|TestADisagreement|TestTwoQualifying|TestAnUnknownKeyType|TestTheDHCPCase|TestAnAddressHandover
//
// mutate:case    independence is counted by key TYPE rather than by service
// mutate:old     moderate[k.Source] = true
// mutate:new     moderate[string(k.Type)] = true
//
// The independence clause counts by SOURCE, and counting distinct key TYPES is
// the plausible wrong implementation: a certificate and a hostname key lifted
// from the SAME service look like two facts and are one. The first attempt at
// this mutation declared an unused variable and changed no behaviour, which
// `make mutate` reported rather than counting as killed.
//
// mutate:case    an address handover attaches instead of queuing (ADR-094)
// mutate:old     			if len(s.conflicts) > 0 {
// mutate:new     			if false {
//
// mutate:case    a renewed certificate at the held address stays a contradiction (ADR-094)
// mutate:old     			if len(certs) > 0 {
// mutate:new     			if false {
//
// mutate:case    a disagreement at equal strength is outvoted by agreement
// mutate:old     if len(s.agreeing) > 0 && maxStrength(s.conflicts) >= maxStrength(s.agreeing) {
// mutate:new     if len(s.agreeing) > 0 && maxStrength(s.conflicts) > maxStrength(s.agreeing) {
//
// mutate:case    weak evidence alone is enough to merge
// mutate:old     case len(moderate) == 1 && weak > 0:
// mutate:new     case weak > 0:
//
// mutate:case    the ip_window key has no window
// mutate:old     return !c.AddressLastSeen.Before(now.Add(-window))
// mutate:new     return true
//
// mutate:case    an unranked key type is treated as evidence
// mutate:old     if o.Type.Strength() == 0 {
// mutate:new     if false {
//
// mutate:case    an attach does not compare the address it is attaching to
// mutate:old     		atHeldAddress := observedAddress != "" && c.HeldAddress == observedAddress &&
// mutate:new     		atHeldAddress := observedAddress != "" &&
//
// That was the original form. It attaches an observation of one address to an
// asset holding another, on the strength of a timestamp the caller filled in — a
// test fixture made exactly that mistake, which is why the address is compared
// rather than the convention trusted.

func key(t IdentityKeyType, value, source string) IdentityKey {
	return IdentityKey{Type: t, Value: value, Source: source}
}

var (
	assetA = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	assetB = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	at     = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	window = 24 * time.Hour
)

// TestOneStrongKeyIsEnoughOnItsOwn.
func TestOneStrongKeyIsEnoughOnItsOwn(t *testing.T) {
	observed := []IdentityKey{key(KeyAgentUUID, "abc", "agent")}
	got := Resolve(observed, []Candidate{{AssetID: assetA, Keys: observed}}, at, window)

	if got.Decision != DecisionMerge || got.AssetID != assetA {
		t.Fatalf("decision = %v asset = %v, want merge with A", got.Decision, got.AssetID)
	}
	if len(got.Agreeing) != 1 {
		t.Errorf("agreeing = %v, want the key that justified it recorded", got.Agreeing)
	}
}

// TestTwoModerateKeysMergeOnlyWhenIndependent.
//
// ============================================================================
// The clause most likely to be implemented wrong, so it is tested from both
// sides.
// ============================================================================
//
// An SSH host key and a TLS certificate are two independent facts about a host.
// Two TLS certificates on two ports are ONE fact observed twice — a wildcard
// certificate deployed to 443 and 8443 — and counting them as two would merge on
// evidence that is really singular.
func TestTwoModerateKeysMergeOnlyWhenIndependent(t *testing.T) {
	independent := []IdentityKey{
		key(KeySSHHostKey, "SHA256:aaa", "22/tcp"),
		key(KeyServiceCert, "SHA256:bbb", "443/tcp"),
	}
	got := Resolve(independent, []Candidate{{AssetID: assetA, Keys: independent}}, at, window)
	if got.Decision != DecisionMerge {
		t.Errorf("two keys from different services did not merge: %v (%s)", got.Decision, got.Reason)
	}

	// The same certificate, seen on two ports of the same service endpoint.
	sameSource := []IdentityKey{
		key(KeyServiceCert, "SHA256:wildcard", "443/tcp"),
		key(KeyServiceCert, "SHA256:wildcard", "443/tcp"),
	}
	got = Resolve(sameSource, []Candidate{{AssetID: assetA, Keys: sameSource}}, at, window)
	if got.Decision == DecisionMerge {
		t.Error("one fact observed twice merged as though it were two independent keys")
	}

	// And two DIFFERENT certificates that both came from the same port — which
	// is what a rotation mid-scan looks like — are still one source.
	oneSource := []IdentityKey{
		key(KeyServiceCert, "SHA256:ccc", "8443/tcp"),
		key(KeyHostnameOS, "host.example/linux", "8443/tcp"),
	}
	got = Resolve(oneSource, []Candidate{{AssetID: assetA, Keys: oneSource}}, at, window)
	if got.Decision == DecisionMerge {
		t.Errorf("two moderate keys from ONE service merged: %s", got.Reason)
	}
}

// TestAModerateKeyPlusAWeakOneMerges.
func TestAModerateKeyPlusAWeakOneMerges(t *testing.T) {
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:aaa", "22/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	got := Resolve(observed, []Candidate{{AssetID: assetA, Keys: observed}}, at, window)
	if got.Decision != DecisionMerge {
		t.Fatalf("decision = %v (%s), want merge", got.Decision, got.Reason)
	}
}

// TestWeakEvidenceAttachesAndNeverMerges.
//
// ADR-007: IP alone never merges. But an open port on a host with no TLS and no
// SSH is the commonest observation in the system, and the alternatives to
// attaching are an inventory that grows on every scan or a queue that does.
//
// Attaching records no identity key. It says "this address currently belongs to
// that asset", which the address table already claims and which expires on its
// own.
func TestWeakEvidenceAttachesAndNeverMerges(t *testing.T) {
	observed := []IdentityKey{key(KeyIPWindow, "10.10.0.11", "net")}
	inWindow := Candidate{
		AssetID: assetA, Keys: observed,
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Hour),
	}

	got := Resolve(observed, []Candidate{inWindow}, at, window)
	if got.Decision != DecisionAttach || got.AssetID != assetA {
		t.Fatalf("decision = %v (%s), want attach to A", got.Decision, got.Reason)
	}
	if len(got.Agreeing) != 0 {
		t.Error("an attach recorded identity keys; only a merge may do that")
	}

	// Outside the window the address is evidence of nothing, and the observation
	// becomes a new asset rather than being attached to a stale holder.
	stale := inWindow
	stale.AddressLastSeen = at.Add(-30 * 24 * time.Hour)
	got = Resolve(observed, []Candidate{stale}, at, window)
	if got.Decision != DecisionNewAsset {
		t.Errorf("decision = %v (%s), want a new asset: the window is the whole meaning of "+
			"`IP within a time window`", got.Decision, got.Reason)
	}
}

// TestADisagreementAtEqualStrengthIsNotOutvoted.
//
// A candidate whose SSH host key contradicts the observed one has said something
// that matters more than any number of agreeing addresses. Letting weight of
// agreement carry the decision is how a merge happens for reasons nobody can
// reconstruct.
func TestADisagreementAtEqualStrengthIsNotOutvoted(t *testing.T) {
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:observed", "22/tcp"),
		key(KeyServiceCert, "SHA256:shared", "443/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	held := []IdentityKey{
		key(KeySSHHostKey, "SHA256:DIFFERENT", "22/tcp"), // same source, other value
		key(KeyServiceCert, "SHA256:shared", "443/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}

	got := Resolve(observed, []Candidate{{AssetID: assetA, Keys: held}}, at, window)
	if got.Decision != DecisionQueue {
		t.Fatalf("decision = %v (%s), want queue: a moderate key contradicts while a "+
			"moderate and a weak agree", got.Decision, got.Reason)
	}
	if len(got.Candidates) != 1 || got.Candidates[0] != assetA {
		t.Errorf("candidates = %v, want the contested asset offered to an operator", got.Candidates)
	}
}

// TestTwoQualifyingCandidatesGoToTheQueue.
//
// They cannot all be this host, and choosing between them is the wrong merge.
func TestTwoQualifyingCandidatesGoToTheQueue(t *testing.T) {
	observed := []IdentityKey{key(KeyAgentUUID, "abc", "agent")}
	got := Resolve(observed, []Candidate{
		{AssetID: assetA, Keys: observed},
		{AssetID: assetB, Keys: observed},
	}, at, window)

	if got.Decision != DecisionQueue {
		t.Fatalf("decision = %v (%s), want queue", got.Decision, got.Reason)
	}
	if len(got.Candidates) != 2 {
		t.Errorf("candidates = %v, want both offered", got.Candidates)
	}
}

// TestAnAddressHandoverIsQueuedNotAttached.
//
// A different host on a reused address: the candidate holds the address inside
// the window (weak agreement, which is not stored as a key and so never counts
// as agreement), and its SSH host key from the same service contradicts the
// observed one. Nothing agrees, so the not-outvoted guard above cannot fire,
// and before ADR-094 this fell through to ATTACH — the newcomer's observations
// and findings interleaved with the previous occupant's, and its key was
// recorded on the occupant's asset. A contradiction at the held address is an
// operator's call. A contradiction with no address tie is unchanged: a new
// asset (TestAnUnknownKeyTypeIsNotEvidence's second case).
func TestAnAddressHandoverIsQueuedNotAttached(t *testing.T) {
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:newcomer", "22/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	// What the store actually hands the resolver: the asset's RECORDED keys.
	// Weak keys are never recorded (the address lives in asset_addresses), so
	// nothing here can agree — which is exactly why the not-outvoted guard,
	// which needs an agreement, could not catch this shape. A held ip_window
	// key in this fixture would make that older guard fire and prove nothing.
	held := []IdentityKey{
		key(KeySSHHostKey, "SHA256:occupant", "22/tcp"), // same source, other value
	}
	got := Resolve(observed, []Candidate{{AssetID: assetA, Keys: held,
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionQueue {
		t.Fatalf("decision = %v (%s), want queue: the address says this asset and the "+
			"host key says another host", got.Decision, got.Reason)
	}
	if len(got.Candidates) != 1 || got.Candidates[0] != assetA {
		t.Errorf("candidates = %v, want the contested asset offered to an operator", got.Candidates)
	}

	// A renewed CERTIFICATE at the held address is not a handover: it attaches
	// (a renewal is the same host, and every TLS host renews on a schedule),
	// and the contradicting certificate is carried out so the caller does not
	// record it — the old one stays the asset's, until a rule retires it.
	got = Resolve(
		[]IdentityKey{key(KeyServiceCert, "SHA256:renewed", "443/tcp"), key(KeyIPWindow, "10.10.0.11", "net")},
		[]Candidate{{AssetID: assetA, Keys: []IdentityKey{key(KeyServiceCert, "SHA256:expired", "443/tcp")},
			HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionAttach {
		t.Fatalf("decision = %v (%s), want attach: a renewed certificate is not a different host", got.Decision, got.Reason)
	}
	if len(got.Contradicted) != 1 || got.Contradicted[0].Value != "SHA256:renewed" {
		t.Errorf("contradicted = %v, want the renewed certificate carried out, unrecorded", got.Contradicted)
	}
	if len(got.Corroborated) != 0 {
		t.Errorf("corroborated = %v, want none: nothing but the address ties this to the asset", got.Corroborated)
	}
	// The common host: a steady SSH key AND a renewed certificate. The
	// agreeing key would otherwise make the renewed certificate an
	// equal-strength contradiction for the not-outvoted guard, and every Linux
	// web server would park at its next renewal. The certificate is filtered
	// before that guard at the held address; the ssh agreement alone does not
	// merge (one moderate key), so this attaches with the certificate carried
	// out.
	got = Resolve(
		[]IdentityKey{
			key(KeySSHHostKey, "SHA256:steady", "22/tcp"),
			key(KeyServiceCert, "SHA256:renewed", "443/tcp"),
			key(KeyIPWindow, "10.10.0.11", "net"),
		},
		[]Candidate{{AssetID: assetA, Keys: []IdentityKey{
			key(KeySSHHostKey, "SHA256:steady", "22/tcp"),
			key(KeyServiceCert, "SHA256:expired", "443/tcp"),
		}, HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionAttach {
		t.Fatalf("decision = %v (%s), want attach: a steady host key and a renewed certificate is the same host", got.Decision, got.Reason)
	}
	if len(got.Contradicted) != 1 || got.Contradicted[0].Value != "SHA256:renewed" {
		t.Errorf("contradicted = %v, want the renewed certificate carried out", got.Contradicted)
	}
	if len(got.Corroborated) != 1 || got.Corroborated[0].Value != "SHA256:steady" {
		t.Errorf("corroborated = %v, want the steady host key: it is what makes the contradiction a renewal", got.Corroborated)
	}
	// Two independent agreeing keys plus a renewed certificate at the held
	// address MERGE (ADR-007), and the merge carries the renewal out the same
	// way an attach does — otherwise the held certificate would never be
	// retired on that path.
	got = Resolve(
		[]IdentityKey{
			key(KeySSHHostKey, "SHA256:steady", "22/tcp"),
			key(KeyServiceCert, "SHA256:steady-cert", "8443/tcp"),
			key(KeyServiceCert, "SHA256:renewed", "443/tcp"),
			key(KeyIPWindow, "10.10.0.11", "net"),
		},
		[]Candidate{{AssetID: assetA, Keys: []IdentityKey{
			key(KeySSHHostKey, "SHA256:steady", "22/tcp"),
			key(KeyServiceCert, "SHA256:steady-cert", "8443/tcp"),
			key(KeyServiceCert, "SHA256:expired", "443/tcp"),
		}, HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionMerge {
		t.Fatalf("decision = %v (%s), want merge: two independent keys agree at the held address", got.Decision, got.Reason)
	}
	if len(got.Contradicted) != 1 || got.Contradicted[0].Value != "SHA256:renewed" || len(got.Corroborated) != 2 {
		t.Errorf("merge carried contradicted=%v corroborated=%v, want the renewed certificate and both agreeing keys", got.Contradicted, got.Corroborated)
	}

	// At a DIFFERENT address, a changed certificate beside an agreeing key is
	// still the ADR-007 contested case: queue.
	got = Resolve(
		[]IdentityKey{
			key(KeySSHHostKey, "SHA256:steady", "22/tcp"),
			key(KeyServiceCert, "SHA256:other", "443/tcp"),
			key(KeyIPWindow, "10.10.0.99", "net"),
		},
		[]Candidate{{AssetID: assetA, Keys: []IdentityKey{
			key(KeySSHHostKey, "SHA256:steady", "22/tcp"),
			key(KeyServiceCert, "SHA256:expired", "443/tcp"),
		}, HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionQueue {
		t.Errorf("decision = %v (%s), want queue: at another address a changed certificate is not a renewal we can see", got.Decision, got.Reason)
	}

	// The same newcomer key with NO contradiction — the occupant holds no key
	// of that type — still attaches: nothing disagrees, and the attach records
	// the key at attach provenance (ADR-094), which the store keeps out of the
	// trust root until seen again.
	got = Resolve(observed, []Candidate{{AssetID: assetA,
		Keys:        nil,
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionAttach {
		t.Errorf("decision = %v (%s), want attach when nothing contradicts", got.Decision, got.Reason)
	}
}

// TestAnUnknownKeyTypeIsNotEvidence.
//
// Zero strength is deliberately not weak. A key type from a build that knows
// something this one does not is not evidence of any strength, and ranking it
// would assert a ranking nobody wrote down.
func TestAnUnknownKeyTypeIsNotEvidence(t *testing.T) {
	observed := []IdentityKey{
		key("quantum_entanglement_id", "spooky", "future"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	held := observed

	got := Resolve(observed, []Candidate{{AssetID: assetA, Keys: held,
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionAttach {
		t.Fatalf("decision = %v (%s), want attach on the weak key alone — the unknown type "+
			"must contribute nothing", got.Decision, got.Reason)
	}

	// ================================================================
	// The case where it actually bites, which the above does not reach.
	// ================================================================
	//
	// An unknown key AGREES and a strong key CONTRADICTS. If the unknown type
	// counted as evidence there would be an agreement for the strong key to
	// contradict, and this would be queued for an operator to adjudicate a
	// conflict between one thing we recognise and one we do not. Treating the
	// unrecognised key as nothing makes it what it is: a different host.
	//
	// Found by a surviving mutation. The first version of this test asserted the
	// unknown type changed no outcome, which was true and is also true when the
	// guard is deleted.
	got = Resolve(
		[]IdentityKey{
			key("quantum_entanglement_id", "same", "future"),
			key(KeyAgentUUID, "observed", "agent"),
		},
		[]Candidate{{AssetID: assetA, Keys: []IdentityKey{
			key("quantum_entanglement_id", "same", "future"),
			key(KeyAgentUUID, "DIFFERENT", "agent"),
		}}}, at, window)
	if got.Decision != DecisionNewAsset {
		t.Errorf("decision = %v (%s), want a new asset: an unrecognised key is not an "+
			"agreement for a strong key to contradict", got.Decision, got.Reason)
	}
}

// TestTheDHCPCaseResolvesToOneAsset.
//
// ============================================================================
// Week 5's deliverable, at the level this package decides it.
// ============================================================================
//
// Scan the lab, the host's address changes, scan again, get ONE asset. The
// address disagrees and the SSH host key does not, so the moderate key carries
// it — which is exactly why the host-key probe was worth a protocol
// implementation (ADR-049).
func TestTheDHCPCaseResolvesToOneAsset(t *testing.T) {
	// What the asset holds from the first scan.
	held := []IdentityKey{
		key(KeySSHHostKey, "SHA256:stable", "22/tcp"),
		key(KeyServiceCert, "SHA256:cert", "443/tcp"),
		key(KeyIPWindow, "10.10.0.11", "net"),
	}
	// The second scan: same host, new address.
	observed := []IdentityKey{
		key(KeySSHHostKey, "SHA256:stable", "22/tcp"),
		key(KeyServiceCert, "SHA256:cert", "443/tcp"),
		key(KeyIPWindow, "10.10.0.77", "net"),
	}

	got := Resolve(observed, []Candidate{{AssetID: assetA, Keys: held}}, at, window)
	if got.Decision != DecisionMerge || got.AssetID != assetA {
		t.Fatalf("decision = %v (%s), want one asset across the address change",
			got.Decision, got.Reason)
	}

	// And with only the address — no TLS, no SSH — the same host at a new
	// address is a new asset. That is the designed degradation, and it is what
	// makes the two moderate keys worth having.
	// The candidate still holds the OLD address, so nothing attaches: the
	// comparison is against the address the asset actually has.
	bare := []IdentityKey{key(KeyIPWindow, "10.10.0.77", "net")}
	got = Resolve(bare, []Candidate{{AssetID: assetA, Keys: held,
		HeldAddress: "10.10.0.11", AddressLastSeen: at.Add(-time.Minute)}}, at, window)
	if got.Decision != DecisionNewAsset {
		t.Errorf("decision = %v (%s), want a new asset: nothing links the old address to "+
			"the new one", got.Decision, got.Reason)
	}
}
