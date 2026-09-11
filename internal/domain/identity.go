package domain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Asset identity: which host is this, and on what evidence.
//
// ============================================================================
// A PURE function of observations. No I/O, no clock, no database.
// ============================================================================
//
// internal/domain's rule is that identity resolution lives here and must be
// re-runnable over history without re-scanning. That is not tidiness: a merge
// decision is the one thing in this system that cannot be undone by looking
// again, because a wrong merge interleaves two hosts' findings, exposures and
// timelines and afterwards nobody can tell which is which (ADR-007). Being able
// to replay every decision against a changed rule, from stored observations, is
// what makes the rule correctable.
//
// # The ranked-key scheme, and what it costs
//
// ADR-007 ranks keys by strength and says a merge requires one strong key or
// "corroborating agreement among weaker ones". This file is where that sentence
// becomes a number.

// IdentityKeyType is ADR-007's key vocabulary. The values match the
// `identity_key_type` enum in migration 0007.
type IdentityKeyType string

const (
	// Strong (3): one of these alone justifies a merge.
	KeyAgentUUID IdentityKeyType = "agent_uuid"
	KeyCloudID   IdentityKeyType = "cloud_id"
	KeyDMIUUID   IdentityKeyType = "dmi_uuid"
	KeyTPMCertFP IdentityKeyType = "tpm_cert_fp"
	KeyHostCert  IdentityKeyType = "host_cert_fp"

	// Moderate (2): corroboration required.
	KeySSHHostKey  IdentityKeyType = "ssh_hostkey"
	KeyServiceCert IdentityKeyType = "service_cert_fp"
	KeyHostnameOS  IdentityKeyType = "hostname_domain_os"

	// Weak (1): never merges alone.
	KeyMAC      IdentityKeyType = "mac"
	KeyNetBIOS  IdentityKeyType = "netbios"
	KeyIPWindow IdentityKeyType = "ip_window"
)

// Strength is 3, 2 or 1 — or 0 for a type this build does not know.
//
// Zero is deliberately not weak. An unrecognised key type is a value from a
// build or a pack that knows something this one does not, and treating it as
// evidence of any strength is asserting a ranking nobody wrote down.
func (t IdentityKeyType) Strength() int {
	switch t {
	case KeyAgentUUID, KeyCloudID, KeyDMIUUID, KeyTPMCertFP, KeyHostCert:
		return 3
	case KeySSHHostKey, KeyServiceCert, KeyHostnameOS:
		return 2
	case KeyMAC, KeyNetBIOS, KeyIPWindow:
		return 1
	default:
		return 0
	}
}

// ============================================================================
// Which of ADR-007's keys this build can actually produce.
// ============================================================================
//
// Recorded here rather than left for the next session to rediscover, because a
// key table that is mostly aspirational should say so in one place.
//
// REACHABLE from a network scan today:
//
//	ssh_hostkey      moderate  the SSH key exchange (ADR-049)
//	service_cert_fp  moderate  the leaf certificate's SHA-256
//	ip_window        weak      the address, inside a window
//
// UNREACHABLE, and what each needs:
//
//	agent_uuid   an agent. Out of MVP scope (execution-plan §2).
//	cloud_id     cloud metadata. Out of MVP scope.
//	dmi_uuid     a credentialed read of the host's DMI table. Credentialed
//	             assessment is out of MVP scope.
//	tpm_cert_fp  a TPM attestation path. Out of MVP scope.
//	host_cert_fp a host certificate the scanner can see, which in practice
//	             means an agent or a mutually-authenticated service.
//	mac          ARP, which needs a raw socket (deferred, ADR-047).
//	netbios      an SMB or NetBIOS name query, which the corpus has no probe
//	             for and which would need a new probe kind.
//	hostname_domain_os  a hostname the scanner can trust plus a consistent OS
//	             fingerprint. Certificate SANs give a hostname the TARGET chose,
//	             and the OS hint is explicitly non-authoritative (ADR-048 §9),
//	             so composing them would be a moderate key built from two
//	             things this codebase says not to trust. Needs real OS
//	             fingerprinting, which is Phase 3.
//
// The consequence, stated so nobody is surprised by it: an estate with no TLS
// and no SSH has only `ip_window`, and ADR-007 says that never merges. Those
// hosts accumulate a new asset whenever their address changes. That is the
// designed degradation — identity quality falls off gracefully rather than
// guessing — and it is why the two moderate keys were worth a session each.

// IdentityKey is one piece of evidence about which host this is.
type IdentityKey struct {
	Type  IdentityKeyType
	Value string

	// Source names the SERVICE that produced this key — "22/tcp", "443/tcp".
	//
	// ========================================================================
	// This is what makes two moderate keys INDEPENDENT, and the clause is the
	// one most likely to be implemented wrong.
	// ========================================================================
	//
	// Two moderate keys corroborate each other only when they come from
	// different services on the host. An SSH host key and a TLS certificate are
	// two independent facts. Two TLS certificates from two ports of the same
	// host are ONE fact observed twice — a single wildcard certificate deployed
	// on 443 and 8443 — and counting them as two would merge on evidence that is
	// really singular, which is exactly the wrong merge ADR-007 exists to
	// prevent.
	Source string

	// ObservationID and Payload are the merge evidence ADR-007 requires to be
	// recorded AND copied. The copy is what lets a merge stay auditable after
	// the observation partition drops (ADR-016).
	ObservationID uuid.UUID
	Payload       []byte
}

// Candidate is an existing asset and the live keys it holds.
type Candidate struct {
	AssetID uuid.UUID
	Keys    []IdentityKey

	// HeldAddress is the address this candidate CURRENTLY holds, and
	// AddressLastSeen is when it was last seen there. Both are empty when the
	// candidate was found by an identity key rather than by address.
	//
	// The address is carried rather than assumed because the attach rule turns
	// on it being the SAME address. An earlier version took only the timestamp
	// and the caller's word that it referred to the address under consideration.
	//
	// Weak keys are deliberately NOT stored in asset_identity_keys, so this is
	// how a weak agreement is expressed. Storing them would mean a second
	// uniqueness constraint over the address and a second thing to close when a
	// host moves, for evidence ADR-007 says never merges anyway.
	HeldAddress     string
	AddressLastSeen time.Time
}

// Decision is what to do with an observation's evidence.
type Decision int

const (
	// DecisionNewAsset: nothing known matches. Create one.
	DecisionNewAsset Decision = iota

	// DecisionAttach: this observation belongs to an existing asset on WEAK
	// evidence only — the asset currently holds the observed address and was
	// seen there inside the window.
	//
	// ====================================================================
	// Attaching is not merging, and the difference is ADR-007's "IP alone
	// never merges" made operational.
	// ====================================================================
	//
	// An attach records no identity key AS EVIDENCE OF THE ATTACH. It says
	// "this address currently belongs to that asset", which is a claim the
	// address table already makes and which expires on its own. A merge says
	// "these are the same host", which is permanent and interleaves two
	// histories. The correlator does still record the moderate keys the
	// attached observation carried on the asset — a host key seen at an address
	// an asset holds is a fact about that asset, and the next scan needs it to
	// merge across an address change (ADR-093); it is not evidence that two
	// assets are one.
	//
	// Without this case the resolver has only bad options for the commonest
	// observation in the system — an open port on a host with no TLS and no SSH:
	// create a new asset on every scan, which explodes the inventory, or queue
	// it, which explodes the queue. Neither is what an operator means by "scan
	// this /24 again".
	DecisionAttach

	// DecisionMerge: evidence sufficient under ADR-007. The identity keys are
	// recorded on the asset with their merge evidence.
	DecisionMerge

	// DecisionQueue: conflicting or ambiguous. A human decides (ADR-007,
	// migration 0013). Never a guess.
	DecisionQueue
)

func (d Decision) String() string {
	switch d {
	case DecisionNewAsset:
		return "new_asset"
	case DecisionAttach:
		return "attach"
	case DecisionMerge:
		return "merge"
	default:
		return "queue"
	}
}

// Verdict is the resolver's answer, with the evidence that produced it.
type Verdict struct {
	Decision Decision

	// AssetID is set for Attach and Merge.
	AssetID uuid.UUID

	// Agreeing are the keys that justified a merge, in strength order. These are
	// what get written to asset_identity_keys with their copied payloads.
	Agreeing []IdentityKey

	// Candidates is what a queued decision offers an operator to choose between.
	Candidates []uuid.UUID

	// Contradicted are observed keys an ATTACH must not simply record
	// (ADR-094): a key of a type that rotates on a schedule (a certificate)
	// which differs from the one the asset holds from the same service. The
	// attach stands — a renewed certificate is the same host — and what the
	// caller does with the new value depends on Corroborated.
	Contradicted []IdentityKey

	// Corroborated are the observed keys that AGREED with the attached asset
	// (its steady SSH host key, say) on an attach that also carries a
	// Contradicted key. With corroboration the contradiction is a renewal:
	// the old key is retired and the new one recorded. Without it — nothing
	// in common with the asset but the address — it is a different host
	// wearing the address, and the caller records nothing at all.
	Corroborated []IdentityKey

	// Reason is read by a human deciding a judgement call. Free text on purpose.
	Reason string
}

// Resolve decides which asset an observation's evidence belongs to.
//
// ============================================================================
// THE RULE (ADR-007, made numeric here):
//
//	one STRONG key agreeing                                    -> merge
//	two INDEPENDENT MODERATE keys agreeing                     -> merge
//	one moderate agreeing + one weak agreeing, none disagreeing -> merge
//	weak alone                                                 -> never merges
//	disagreement at equal-or-higher strength                   -> queue
//	more than one candidate qualifying                         -> queue
//
// ============================================================================
//
// `now` and `window` are parameters rather than reads, because this function is
// re-run over history: a decision replayed next year must reach the answer it
// reached at the time, and a clock read inside would make that impossible.
func Resolve(observed []IdentityKey, candidates []Candidate, now time.Time, window time.Duration) Verdict {
	// scored is a candidate plus what the evidence says about it.
	type scored struct {
		c         Candidate
		agreeing  []IdentityKey
		conflicts []IdentityKey
		merges    bool
		why       string
	}
	scoredIDs := func(in []scored) []uuid.UUID {
		out := make([]uuid.UUID, 0, len(in))
		for _, s := range in {
			out = append(out, s.c.AssetID)
		}
		return out
	}

	var (
		contested  []scored
		qualified  []scored
		attachable []Candidate
	)

	// The address this evidence is about, which is what an attach compares
	// against. Empty when the observation carried none, and then nothing
	// attaches.
	var observedAddress string
	for _, k := range observed {
		if k.Type == KeyIPWindow {
			observedAddress = k.Value
			break
		}
	}

	contradicted := map[uuid.UUID][]IdentityKey{}
	corroborated := map[uuid.UUID][]IdentityKey{}
	for _, c := range candidates {
		s := scored{c: c}
		s.agreeing, s.conflicts = compare(observed, c.Keys)
		s.merges, s.why = mergeRule(s.agreeing)

		// ================================================================
		// Disagreement at equal-or-higher strength is NOT outvoted.
		// ================================================================
		//
		// A candidate whose SSH host key contradicts the observed one has told
		// us something that matters more than a hundred agreeing addresses. The
		// alternative — letting weight of agreement carry the decision — is how
		// a merge happens for reasons nobody can reconstruct afterwards.
		//
		// One class of contradiction is filtered out BEFORE that guard, and only
		// for the candidate that holds this address: a different CERTIFICATE
		// from the same service. A certificate renews on a schedule (ACME, every
		// 60–90 days, on every TLS host) and an SSH host key does not, so at the
		// host's own address a changed certificate is a renewal, not a
		// different host — and the review measured that leaving it in the
		// conflict set parked every Linux web server (steady sshd, renewed
		// cert: agreeing ssh, conflicting cert, contested) at its next renewal,
		// forever. The certificate is not discarded: it travels out as
		// Contradicted, and the caller retires the held one and records it
		// when the attach is corroborated by an ESTABLISHED key, or records
		// nothing when it is not. A contradicting certificate at a
		// DIFFERENT address is left in the set — that candidate was found by a
		// key, and a changed certificate there is not a renewal we can see.
		atHeldAddress := observedAddress != "" && c.HeldAddress == observedAddress &&
			holdsAddressInWindow(c, now, window)
		if atHeldAddress {
			var certs, rest []IdentityKey
			for _, k := range s.conflicts {
				if k.Type == KeyServiceCert {
					certs = append(certs, k)
				} else {
					rest = append(rest, k)
				}
			}
			// Certificates only — named, not "everything that is not an SSH
			// key": a key type this build cannot produce yet (a DMI UUID, an
			// OS-fingerprint key) that contradicts at the held address must
			// still reach the guard below, or a merge could go through on a
			// contradiction nobody carried out.
			if len(certs) > 0 {
				contradicted[c.AssetID] = certs
				s.conflicts = rest
			}
		}
		if len(s.agreeing) > 0 && maxStrength(s.conflicts) >= maxStrength(s.agreeing) {
			contested = append(contested, s)
			continue
		}
		if s.merges {
			qualified = append(qualified, s)
			continue
		}
		// Weak-only: the candidate holds THIS address and was seen at it inside
		// the window.
		//
		// The address is COMPARED, not assumed. An earlier version asked only
		// whether the candidate had been seen somewhere recently and whether the
		// observation carried an address at all — which attaches an observation
		// of 10.10.0.77 to an asset holding 10.10.0.11, on the strength of a
		// field the caller filled in. A test fixture made exactly that mistake.
		if atHeldAddress {
			// ============================================================
			// Address handover: the address says "this asset", a key says
			// "a different host". That is not an attach (ADR-094).
			// ============================================================
			//
			// The guard above fires only when something AGREES, so a
			// newcomer on a reused lease — nothing in common with the asset
			// but the address, and a moderate key from the same service that
			// contradicts the one the asset holds — fell through to attach,
			// and its findings interleaved with the previous occupant's. The
			// contradiction is the stronger fact: the address is weak
			// evidence and the key is moderate, and one moderate key alone
			// decides nothing (ADR-007), so this is an operator's call, not
			// a guess in either direction. A contradiction with NO address
			// tie is unchanged: that candidate was never attachable, and a
			// different host at a different address is a new asset.
			if len(s.conflicts) > 0 {
				s.why = "address handover"
				contested = append(contested, s)
				continue
			}
			// Certificate contradictions were moved to Contradicted above;
			// nothing else contradicts. The attach stands.
			corroborated[c.AssetID] = moderateOrStronger(s.agreeing)
			attachable = append(attachable, c)
		}
	}

	switch {
	case len(contested) > 0:
		reason := fmt.Sprintf(
			"evidence agrees with asset %s at strength %d and contradicts it at strength %d; "+
				"a disagreement at equal or higher strength is not outvoted (ADR-007)",
			contested[0].c.AssetID, maxStrength(contested[0].agreeing),
			maxStrength(contested[0].conflicts))
		if contested[0].why == "address handover" {
			reason = fmt.Sprintf(
				"asset %s holds this address but a key at strength %d contradicts the one it holds "+
					"from the same service; a different host on a reused address is not an attach (ADR-094)",
				contested[0].c.AssetID, maxStrength(contested[0].conflicts))
		}
		return Verdict{
			Decision:   DecisionQueue,
			Candidates: scoredIDs(contested),
			Agreeing:   contested[0].agreeing,
			Reason:     reason,
		}

	case len(qualified) > 1:
		return Verdict{
			Decision:   DecisionQueue,
			Candidates: scoredIDs(qualified),
			Reason: fmt.Sprintf(
				"%d assets each hold evidence sufficient to merge; they cannot all be this host",
				len(qualified)),
		}

	case len(qualified) == 1:
		return Verdict{
			Decision: DecisionMerge,
			AssetID:  qualified[0].c.AssetID,
			Agreeing: qualified[0].agreeing,
			// A merge at the held address can carry a renewed certificate
			// too (the filter above runs before the guard): the agreeing keys
			// ARE the corroboration, and the caller retires and replaces the
			// held certificate exactly as on a corroborated attach.
			Contradicted: contradicted[qualified[0].c.AssetID],
			Corroborated: moderateOrStronger(qualified[0].agreeing),
			Reason:       qualified[0].why,
		}

	case len(attachable) > 1:
		// Two assets claiming the same live address is a defect in the address
		// intervals, not a judgement call — but it is not this function's to
		// fix, and guessing between them is the wrong merge in miniature.
		return Verdict{
			Decision:   DecisionQueue,
			Candidates: assetIDs(attachable),
			Reason: "more than one asset currently holds this address; the address intervals " +
				"disagree and no stronger key separates them",
		}

	case len(attachable) == 1:
		return Verdict{
			Decision:     DecisionAttach,
			AssetID:      attachable[0].AssetID,
			Contradicted: contradicted[attachable[0].AssetID],
			Corroborated: corroborated[attachable[0].AssetID],
			Reason: fmt.Sprintf(
				"the asset holds this address and was seen at it within %s; weak evidence "+
					"attaches an observation and never merges identity (ADR-007)", window),
		}

	default:
		return Verdict{Decision: DecisionNewAsset, Reason: "no candidate matched any observed key"}
	}
}

// mergeRule applies ADR-007's corroboration rule to a set of agreeing keys.
func mergeRule(agreeing []IdentityKey) (bool, string) {
	var strong, weak int
	moderate := map[string]bool{} // by SOURCE — see IdentityKey.Source

	for _, k := range agreeing {
		switch k.Type.Strength() {
		case 3:
			strong++
		case 2:
			moderate[k.Source] = true
		case 1:
			weak++
		}
	}

	switch {
	case strong > 0:
		return true, "a strong identity key agrees; one is sufficient (ADR-007)"

	case len(moderate) >= 2:
		// INDEPENDENT: counted by distinct source, so two certificates from two
		// ports of the same host are one fact observed twice and do not
		// corroborate each other.
		return true, fmt.Sprintf(
			"two independent moderate keys agree, from %s", strings.Join(sortedKeys(moderate), " and "))

	case len(moderate) == 1 && weak > 0:
		return true, "a moderate key agrees and a weak key corroborates it, with none disagreeing"

	default:
		// Weak alone. Never.
		return false, ""
	}
}

// compare splits a candidate's keys into those that agree with the observed
// evidence and those that contradict it.
//
// Contradiction is same TYPE, different VALUE, and same source: a host with two
// certificates on two ports is not contradicting itself. Without the source
// check, an asset legitimately holding a different certificate on 8443 would
// look like a conflict on every scan and queue forever.
func compare(observed, held []IdentityKey) (agreeing, conflicts []IdentityKey) {
	for _, o := range observed {
		if o.Type.Strength() == 0 {
			continue // a type this build does not rank is not evidence
		}
		for _, h := range held {
			if h.Type != o.Type {
				continue
			}
			if h.Value == o.Value {
				agreeing = append(agreeing, o)
				continue
			}
			if h.Source == o.Source {
				conflicts = append(conflicts, o)
			}
		}
	}
	return dedupe(agreeing), dedupe(conflicts)
}

func dedupe(in []IdentityKey) []IdentityKey {
	seen := map[string]bool{}
	out := in[:0]
	for _, k := range in {
		id := string(k.Type) + "\x00" + k.Value + "\x00" + k.Source
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, k)
	}
	return out
}

// moderateOrStronger keeps the keys that can corroborate: a weak key is the
// address, and the address must never corroborate a contradiction at itself.
// Weak keys are not recorded today, so this is a guard against the convention
// rather than a live filter.
func moderateOrStronger(keys []IdentityKey) []IdentityKey {
	var out []IdentityKey
	for _, k := range keys {
		if k.Type.Strength() >= 2 {
			out = append(out, k)
		}
	}
	return out
}

func maxStrength(keys []IdentityKey) int {
	m := 0
	for _, k := range keys {
		if s := k.Type.Strength(); s > m {
			m = s
		}
	}
	return m
}

// holdsAddressInWindow is what makes `ip_window` a window rather than a label.
//
// ADR-007 ranks the key "IP within a time window" and the window is the whole
// of its meaning: an address seen on this asset a minute ago is reasonable
// evidence the host has not changed, and the same address last seen three months
// ago is evidence of nothing. Outside the window the observation becomes a new
// asset and the stale interval is closed by the caller.
func holdsAddressInWindow(c Candidate, now time.Time, window time.Duration) bool {
	if c.AddressLastSeen.IsZero() {
		return false
	}
	return !c.AddressLastSeen.Before(now.Add(-window))
}

func assetIDs(cs []Candidate) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.AssetID)
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
