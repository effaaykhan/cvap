package domain

import (
	"sort"
	"strings"
)

// Release resolution from unauthenticated service versions (P3.3, ADR-064).
//
// ============================================================================
// PURE, like AttributeOS: correlate gathers each service's observed upstream
// band and the releases the advisory keyspace says share that band, and this
// applies the verdict. The ranking and the threshold live here so they are one
// place to read and one ADR to revise.
// ============================================================================
//
// The method is upstream-BAND matching (session-30 measurement, ADR-064): Ubuntu
// bumps a package's upstream version every release, so hardy's `openssh 4.7p1`,
// `apache2 2.2.8`, `mysql 5.0.51a` are each unique in the keyspace and the band
// alone pins the release — no packaging suffix, no per-release rename map.
//
// Every failure mode is UNRESOLVED, never wrong (ADR-064's safety property): a
// band collision (apache2 2.2.22 across precise/quantal) yields two candidates
// and no clean vote; an absent release yields no match; a swapped-in build
// (Metasploitable's Samba 3.0.20) matches nothing and abstains. Unresolved is a
// representable state (ADR-061's nullable DistroRelease) that honestly means
// unmatched for advisories — which is why inference is acceptable here at all.

// UpstreamBand is the release-discriminating token: a Debian/Ubuntu version with
// the epoch and the packaging revision stripped. `1:4.7p1-8ubuntu1.2` -> `4.7p1`,
// `5.0.51a-3ubuntu5` -> `5.0.51a`, `4.7p1` -> `4.7p1`. It is the ONE authority for
// what a band is — used for both the observed version and the keyspace fixed
// versions — so SQL never extracts a band and the two cannot diverge (the
// two-writers-one-fact hazard, and ADR-062: version semantics live in Go).
func UpstreamBand(version string) string {
	v := strings.TrimSpace(version)
	if i := strings.Index(v, ":"); i >= 0 { // strip epoch
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, "-"); i >= 0 { // strip the Debian revision
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// ReleaseRole records how a service's vote related to the resolved release, so
// the basis of the claim is reachable when it is wrong (the same reason a finding
// carries its evidence). Release resolution adds a fourth role AttributeOS does
// not need: ABSTAINED, because "absence is not evidence" must be VISIBLE — an
// operator has to be able to see which services could not vote and why, or a
// release with three votes looks identical to one with three votes and four
// silent mismatches.
type ReleaseRole string

const (
	// ReleaseContributed: a clean single-release vote for the resolved release.
	ReleaseContributed ReleaseRole = "contributed"
	// ReleaseAgreed: candidates include the resolved release but are ambiguous
	// (a band collision), so it corroborates without pinning.
	ReleaseAgreed ReleaseRole = "agreed"
	// ReleaseIgnored: a clean vote for a DIFFERENT release — dissent. Recorded,
	// not dropped: the dissenting host (a swapped build, a backport) is what a
	// wrong precedence or a Frankenstein image looks like.
	ReleaseIgnored ReleaseRole = "ignored"
	// ReleaseAbstained: cast no vote — no keyspace analogue for the product, or
	// the observed band matched no release. NOT a vote against (ADR-064).
	ReleaseAbstained ReleaseRole = "abstained"
)

// ReleaseVote is one service's input. Candidates is the set of releases whose
// keyspace band equals the observed Band, computed by the caller with
// UpstreamBand over the store's rows. HasAnalogue is false when the product maps
// to no keyspace package at all — distinct from "mapped, but the band matched no
// release", because the two abstentions mean different things to an operator.
type ReleaseVote struct {
	Service     string
	Port        uint16
	Product     string
	Band        string // observed upstream band; "" when the banner carried no version
	Candidates  []string
	HasAnalogue bool
}

// ReleaseSource is one line of the release provenance chain.
type ReleaseSource struct {
	Service    string      `json:"service"`
	Port       uint16      `json:"port"`
	Product    string      `json:"product"`
	Band       string      `json:"band,omitempty"`
	Role       ReleaseRole `json:"role"`
	Reason     string      `json:"reason,omitempty"`     // why an abstention abstained
	Candidates []string    `json:"candidates,omitempty"` // the releases this service pointed at
}

// ReleaseResolution is the outcome. Release nil = unresolved (family-only stays
// the asset's state); set = resolved and matchable. Provenance lists every
// service's role, abstentions included.
type ReleaseResolution struct {
	Release    *string
	Confidence float32
	Provenance []ReleaseSource
}

// ReleaseVoteThreshold is the number of clean, agreeing single-release votes a
// release needs to be RESOLVED rather than left family-only (ADR-064). Set to 2:
//
//   - one clean vote is not enough — a lone service can be a backport or a
//     swapped-in build that coincidentally band-matches a release, and a wrong
//     release poisons every advisory finding on the host.
//   - two INDEPENDENT services agreeing corroborate each other; the chance two
//     unrelated swapped builds both band-match the same wrong release is low
//     (Metasploitable's two swaps matched NOTHING and abstained, the common case).
//   - three is clearly enough and is what the acceptance host provides.
//
// A tie or a split never resolves: the leader must be unique. Everything short of
// the bar is family-only, never a guessed release.
const ReleaseVoteThreshold = 2

// ResolveRelease applies band voting to the per-service votes. A service casts a
// CLEAN vote only when its candidate set is a single release; a multi-candidate
// set (a band collision) corroborates but never pins, and an empty set or a
// missing analogue abstains. The resolved release is the unique leader by clean
// votes, and only if that leader reaches ReleaseVoteThreshold.
func ResolveRelease(votes []ReleaseVote) ReleaseResolution {
	tally := map[string]int{}
	totalClean := 0
	for _, v := range votes {
		if len(v.Candidates) == 1 {
			tally[v.Candidates[0]]++
			totalClean++
		}
	}

	// Leader by clean votes, deterministic tiebreak by release name so a tie is
	// reproducible (and, being a tie, will not resolve anyway).
	leader, leaderCount, unique := "", 0, false
	names := make([]string, 0, len(tally))
	for r := range tally {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		switch {
		case tally[r] > leaderCount:
			leader, leaderCount, unique = r, tally[r], true
		case tally[r] == leaderCount:
			unique = false
		}
	}

	resolved := leaderCount >= ReleaseVoteThreshold && unique

	res := ReleaseResolution{}
	if resolved {
		r := leader
		res.Release = &r
		res.Confidence = releaseConfidence(leaderCount, totalClean)
	}

	for _, v := range votes {
		src := ReleaseSource{
			Service: v.Service, Port: v.Port, Product: v.Product,
			Band: v.Band, Candidates: v.Candidates,
		}
		switch {
		case !v.HasAnalogue:
			src.Role = ReleaseAbstained
			src.Reason = "no advisory package for this product in the keyspace"
		case v.Band == "":
			src.Role = ReleaseAbstained
			src.Reason = "no version was identified for this service"
		case len(v.Candidates) == 0:
			src.Role = ReleaseAbstained
			src.Reason = "observed version matches no release's band"
		case len(v.Candidates) == 1 && v.Candidates[0] == leader && leaderCount > 0:
			src.Role = ReleaseContributed
		case len(v.Candidates) == 1:
			src.Role = ReleaseIgnored // a clean vote for a different release
		case contains(v.Candidates, leader) && leaderCount > 0:
			src.Role = ReleaseAgreed // ambiguous, but consistent with the leader
		default:
			src.Role = ReleaseIgnored // ambiguous and not even consistent
		}
		res.Provenance = append(res.Provenance, src)
	}
	return res
}

// releaseConfidence encodes BOTH corroboration count and unanimity, so the
// finding pipeline can distinguish a two-vote resolution from a four-vote one —
// both resolve, but four agreeing is a stronger claim (ADR-064). The count sets a
// base (2 → 0.80, 3 → 0.90, ≥4 → 0.95), and dissent scales it down by the share
// of clean votes that agree. So a unanimous 2/2 (0.80) outranks a 3/4 with one
// dissenter (0.675) and a 3/5 (0.54) — a clean pair beats a disputed plurality,
// which is the ordering the threshold decision rests on. The bases map onto the
// UI's own bands: two votes reads as "medium", three-plus as "high".
func releaseConfidence(leaderCount, totalClean int) float32 {
	var base float32
	switch {
	case leaderCount >= 4:
		base = 0.95
	case leaderCount == 3:
		base = 0.90
	default: // exactly the threshold, 2
		base = 0.80
	}
	if totalClean == 0 {
		return 0
	}
	return base * float32(leaderCount) / float32(totalClean)
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
