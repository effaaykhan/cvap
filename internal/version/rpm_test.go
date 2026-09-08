package version

import "testing"

// mutate:subject internal/version/rpm.go
// mutate:test    ./internal/version/ -run TestCompareRPM
//
// mutate:case    the rpm tilde ordering is inverted, so a pre-release (1.0~rc1)
//                sorts ABOVE the release — the silent-false-negative shape
// mutate:old     if !oneTilde {
// mutate:new     if oneTilde {
//
// The tilde corpus cases kill it: with the branch inverted, 1.0~rc1 vs 1.0
// returns the wrong sign.

// The rpm comparison corpus — Red Hat's own rpmvercmp test vectors from rpm's
// tests/rpmvercmp.at (the canonical suite). TRANSCRIBED, not fetched: this
// environment has no network, so the vectors are reproduced faithfully from the
// public suite and labelled as such — a network-connected CI could fetch and diff
// them, and that is the honest way to keep them current. Where a vector fails,
// the comparator is fixed, not the vector (ADR-014, ADR-059 P3.1) — after
// confirming the vector itself is a true transcription and not a typo.
//
// Each case is asserted forward, reverse (-want) and reflexive, so a comparator
// right one way and wrong the other cannot pass — the antisymmetry a single
// direction cannot see.
var rpmVectors = []struct {
	a, b string
	want int
}{
	// ---- core numeric / alphabetic segmentation ----
	{"1.0", "1.0", 0},
	{"1.0", "2.0", -1},
	{"2.0", "1.0", 1},
	{"2.0.1", "2.0.1", 0},
	{"2.0", "2.0.1", -1},
	{"2.0.1", "2.0", 1},
	{"2.0.1a", "2.0.1a", 0},
	{"2.0.1a", "2.0.1", 1},
	{"2.0.1", "2.0.1a", -1},
	{"5.5p1", "5.5p1", 0},
	{"5.5p1", "5.5p2", -1},
	{"5.5p2", "5.5p1", 1},
	{"5.5p10", "5.5p10", 0},
	{"5.5p1", "5.5p10", -1}, // p1 vs p10: 1 < 10 numerically, not lexically
	{"5.5p10", "5.5p1", 1},
	{"10xyz", "10.1xyz", -1}, // numeric segment (1) outranks alpha (xyz)
	{"10.1xyz", "10xyz", 1},
	{"xyz10", "xyz10", 0},
	{"xyz10", "xyz10.1", -1},
	{"xyz10.1", "xyz10", 1},
	{"xyz.4", "xyz.4", 0},
	{"xyz.4", "8", -1}, // alpha xyz < numeric 8
	{"8", "xyz.4", 1},
	{"xyz.4", "2", -1},
	{"2", "xyz.4", 1},
	{"5.5p2", "5.6p1", -1},
	{"5.6p1", "5.5p2", 1},
	{"5.6p1", "5.6p1", 0},
	{"5.6p1+git", "5.6p1", 1},
	{"5.6p1", "5.6p1+git", -1},
	{"5.6p1.5", "5.6p1", 1},
	{"5.6p1", "5.6p1.5", -1},

	// ---- tilde sorts before everything, including a segment or end ----
	{"1.0~rc1", "1.0~rc1", 0},
	{"1.0~rc1", "1.0", -1},
	{"1.0", "1.0~rc1", 1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~rc2", "1.0~rc1", 1},
	{"1.0~rc1~git123", "1.0~rc1~git123", 0},
	{"1.0~rc1~git123", "1.0~rc1", -1},
	{"1.0~rc1", "1.0~rc1~git123", 1},

	// ---- caret sorts a version ABOVE its bare base ----
	{"1.0^", "1.0^", 0},
	{"1.0^", "1.0", 1},
	{"1.0", "1.0^", -1},
	{"1.0^git1", "1.0^git1", 0},
	{"1.0^git1", "1.0", 1},
	{"1.0", "1.0^git1", -1},
	{"1.0^git1", "1.0^git2", -1},
	{"1.0^git2", "1.0^git1", 1},
	{"1.0^git1", "1.01", -1},
	{"1.01", "1.0^git1", 1},
	{"1.0^20160101", "1.0^20160101", 0},
	{"1.0^20160101", "1.0.1", -1},
	{"1.0.1", "1.0^20160101", 1},
	{"1.0^20160101^git1", "1.0^20160101^git1", 0},
	{"1.0^20160102", "1.0^20160101^git1", 1},
	{"1.0^20160101^git1", "1.0^20160102", -1},
	{"1.0~rc1^git1", "1.0~rc1^git1", 0},
	{"1.0~rc1^git1", "1.0~rc1", 1},
	{"1.0~rc1", "1.0~rc1^git1", -1},
	{"1.0^git1~pre", "1.0^git1~pre", 0},
	{"1.0^git1", "1.0^git1~pre", 1},
	{"1.0^git1~pre", "1.0^git1", -1},
}

func TestCompareRPMAgainstRedHatCorpus(t *testing.T) {
	pass, fail := 0, 0
	for _, c := range rpmVectors {
		ok := true
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
			ok = false
		}
		if got := CompareRPM(c.b, c.a); got != -c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d (reverse)", c.b, c.a, got, -c.want)
			ok = false
		}
		if got := CompareRPM(c.a, c.a); got != 0 {
			t.Errorf("CompareRPM(%q, %q) = %d, want 0 (reflexive)", c.a, c.a, got)
			ok = false
		}
		if ok {
			pass++
		} else {
			fail++
		}
	}
	t.Logf("rpmvercmp corpus: %d/%d cases pass", pass, pass+fail)
}
