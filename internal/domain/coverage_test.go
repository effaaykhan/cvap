package domain

import "testing"

// The three states must stay distinct; the defect B29 addresses is cannot-know
// collapsing into clean.
func TestClassifyMatch(t *testing.T) {
	cases := []struct {
		matched, inCoverage bool
		want                MatchState
	}{
		{true, true, MatchVulnerable},   // a positive match is trustworthy even in coverage
		{true, false, MatchVulnerable},  // ...and even out of coverage — a found vuln is real
		{false, true, MatchClean},       // no match, feed still covers -> honestly clean
		{false, false, MatchCannotKnow}, // no match, out of coverage -> NOT clean (the B29 fix)
	}
	for _, c := range cases {
		if got := ClassifyMatch(c.matched, c.inCoverage); got != c.want {
			t.Errorf("ClassifyMatch(matched=%t, inCoverage=%t) = %q, want %q", c.matched, c.inCoverage, got, c.want)
		}
	}
}

// AssetAdvisoryStatus (ADR-068): the per-host wire verdict. clean requires BOTH a
// resolved release and coverage; every other combination is something other than
// clean, so a client can never reach "clean" except when the server means it.
func TestAssetAdvisoryStatus(t *testing.T) {
	cases := []struct {
		resolved, inCoverage, anyFinding bool
		want                             MatchState
	}{
		{false, false, false, MatchNoRelease}, // no release -> matching never ran
		{false, true, false, MatchNoRelease},  // coverage irrelevant without a release
		{true, true, false, MatchClean},       // resolved + covered + nothing matched
		{true, false, false, MatchCannotKnow}, // resolved but out of coverage -> NOT clean
		{true, true, true, MatchVulnerable},   // a match, in coverage
		{true, false, true, MatchVulnerable},  // a match stands even out of coverage
	}
	for _, c := range cases {
		if got := AssetAdvisoryStatus(c.resolved, c.inCoverage, c.anyFinding); got != c.want {
			t.Errorf("AssetAdvisoryStatus(resolved=%t,inCov=%t,finding=%t) = %q, want %q",
				c.resolved, c.inCoverage, c.anyFinding, got, c.want)
		}
	}
	// clean is reachable from exactly one input combination.
	if AssetAdvisoryStatus(true, true, false) != MatchClean {
		t.Fatal("clean must be reachable only from resolved+covered+no-finding")
	}
}

// The load-bearing distinction stated once more, explicitly: a no-match must
// produce a DIFFERENT state depending on coverage — never the same one.
func TestNoMatchDiffersByCoverage(t *testing.T) {
	covered := ClassifyMatch(false, true)
	uncovered := ClassifyMatch(false, false)
	if covered == uncovered {
		t.Fatalf("a no-match must differ by coverage: covered=%q uncovered=%q — collapsing them IS the defect", covered, uncovered)
	}
	if uncovered != MatchCannotKnow {
		t.Errorf("out-of-coverage no-match must be cannot_know, got %q", uncovered)
	}
}
