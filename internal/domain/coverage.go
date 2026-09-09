package domain

// Advisory-match state under the coverage window (B29, ADR-067).
//
// ============================================================================
// PURE. The three states are distinct and MUST stay distinct — the whole defect
// B29 addresses is the third collapsing into the second.
// ============================================================================
//
// A release's advisory feed covers only until that release's support ends (EOL,
// or ESM end). A host on a release past that window has real exposure the
// keyspace cannot know about, so a NO-MATCH on it is not evidence of safety — it
// is the absence of evidence. This is the fourth application in the project of
// "absence is not evidence": no advisory for a package, no keyspace analogue for a
// product (ADR-064), no labelled corpus instance for a rule (§5.5), and now no
// advisory coverage for a release.

// MatchState is the verdict for a host's advisory matching, coverage-aware.
type MatchState string

const (
	// MatchVulnerable: an advisory matched (installed < fixed). A positive match
	// is trustworthy whether or not the release is still covered — a found
	// vulnerability is real; coverage only bounds what we might have MISSED.
	MatchVulnerable MatchState = "vulnerable"
	// MatchClean: no advisory matched AND the release is within its coverage
	// window — the feed is still issuing advisories for it, so "no known advisory
	// vulnerability" is an honest answer.
	MatchClean MatchState = "clean"
	// MatchCannotKnow: no advisory matched BUT the release is past its coverage
	// window. The keyspace stopped accumulating for this release, so a no-match
	// says nothing about safety. This must NOT read as clean (B29).
	MatchCannotKnow MatchState = "cannot_know"
)

// ClassifyMatch combines whether any advisory matched with whether the release is
// within advisory coverage. A no-match on an out-of-coverage release is
// cannot-know, never clean. When coverage is UNKNOWN (no window data for the
// release) the honest reading is also cannot-know: we cannot assert the feed
// covers the host, so we do not present its silence as safety.
func ClassifyMatch(anyAdvisoryMatched bool, releaseInCoverage bool) MatchState {
	if anyAdvisoryMatched {
		return MatchVulnerable
	}
	if releaseInCoverage {
		return MatchClean
	}
	return MatchCannotKnow
}
