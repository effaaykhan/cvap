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
