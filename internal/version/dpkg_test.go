package version

import "testing"

// mutate:subject internal/version/dpkg.go
// mutate:test    ./internal/version/ -run TestCompareDpkg
//
// mutate:case    the tilde loses its special rank, so a pre-release (1.0~rc1)
//                sorts ABOVE the release instead of below it
// mutate:old     case c == '~':
// mutate:new     case c == '\a':
//
// mutate:case    the numeric first-difference is inverted, reversing which of two
//                equal-length digit runs is larger (1.0.10 vs 1.0.9)
// mutate:old     firstDiff = int(a[i]) - int(b[j])
// mutate:new     firstDiff = int(b[j]) - int(a[i])
//
// Both are the silent-false-negative shape ADR-014 warns of — a comparator wrong
// on tildes or numeric order judges a vulnerable package safe. The tilde and
// numeric cases in the ordering corpus kill them.

// The dpkg comparison corpus: labelled orderings that MUST hold (ADR-059 P3.1,
// ADR-014). This is the gate — a comparator that only asserts "it runs" or "it is
// transitive" passes while being wrong on epochs or tildes, and a wrong dpkg
// comparison is a SILENT false negative (a vulnerable package judged safe), the
// worst failure a scanner has. So the cases name the orderings, drawn from
// Debian's own dpkg test suite (t-versions) plus the real backport strings this
// session measured.
//
// Each case is {a, b, want} where want is -1 (a<b), 0 (a==b), 1 (a>b). Every case
// is also asserted in reverse (b vs a must give -want) and reflexively (a==a),
// so a comparator that is right one way and wrong the other cannot pass.
var dpkgOrderings = []struct {
	a, b string
	want int
}{
	// ---- the motivating case: a backport revision is NEWER than upstream ----
	// Ubuntu backports a fix into the revision and leaves upstream alone
	// (ADR-014); the installed package must sort ABOVE bare upstream, or matching
	// upstream ranges silently flags it.
	{"2.2.8-1ubuntu0.22", "2.2.8", 1},
	{"1.1.1f-1ubuntu2.16", "1.1.1f", 1},
	{"1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.15", 1},

	// ---- equality, including the default epoch ----
	{"1.0", "1.0", 0},
	{"0:1.0", "1.0", 0}, // an absent epoch is epoch 0
	{"2.2.8", "2.2.8", 0},

	// ---- epoch dominates everything ----
	{"1:1.0", "2.0", 1},   // epoch 1 beats a larger upstream at epoch 0
	{"2:0.1", "1:9.9", 1}, // higher epoch wins outright
	{"1:1.0", "1.0", 1},

	// ---- a revision makes a version larger than the same upstream with none ----
	{"1.0-1", "1.0", 1},
	{"1.0-1", "1.0-2", -1},

	// ---- numeric segments compare as numbers, not lexically ----
	{"1.10", "1.9", 1},
	{"1.0.10", "1.0.9", 1},
	{"0.99", "0.100", -1}, // 100 > 99 numerically, so 0.99 < 0.100

	// ---- the tilde sorts BEFORE everything, even end-of-string ----
	{"1.0~rc1", "1.0", -1}, // a pre-release is older than the release
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~~", "1.0~", -1},
	{"1.0~~a", "1.0~", -1},
	{"1.0~", "1.0", -1},

	// ---- letters sort after a shorter numeric-equal prefix, per order() ----
	{"1.0", "1.0a", -1}, // end-of-string sorts before a letter
	{"1.0a", "1.0b", -1},

	// ---- leading zeros in a numeric segment are not significant ----
	{"1.007", "1.7", 0},
	{"1.0", "1.00", 0},
}

// debianVectors is transcribed from dpkg's own test suite (t-versions /
// Dpkg::Version tests) — TRANSCRIBED, not fetched (no network here), and labelled
// as such the same way the rpm corpus is. Distinct from dpkgOrderings above,
// which are this project's own cases; these are Debian's, so a divergence between
// the two would surface a disagreement rather than a shared assumption.
var debianVectors = []struct {
	a, b string
	want int
}{
	{"1.0-1", "1.0-2", -1},
	{"1.0-1", "1.0", 1},
	{"1.0", "1.0-1", -1},
	{"1.0~rc1", "1.0", -1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~rc1~git1", "1.0~rc1", -1},
	{"1:1.0", "2.0", 1}, // epoch dominates a larger upstream
	{"1:0", "2:0", -1},  // higher epoch wins
	{"2.0", "2.1", -1},
	{"1.2.3", "1.2.3", 0},
	{"1.0", "1.00", 0}, // trailing zero in a numeric segment is not significant
	{"0", "00", 0},
	{"1", "2", -1},
	{"1.0.0", "1.0", 1},
	{"1a", "1", 1}, // a letter after the number sorts above the bare number
	{"1a", "1b", -1},
	{"1.0+nmu1", "1.0", 1},
	{"1.0", "1.0+b1", -1},
	{"3.0-1", "3.0-1", 0},
	{"1:2.3-1", "1:2.3-2", -1},
}

func TestCompareDpkgAgainstDebianCorpus(t *testing.T) {
	pass, fail := 0, 0
	for _, c := range debianVectors {
		ok := true
		if got := CompareDpkg(c.a, c.b); got != c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
			ok = false
		}
		if got := CompareDpkg(c.b, c.a); got != -c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d (reverse)", c.b, c.a, got, -c.want)
			ok = false
		}
		if ok {
			pass++
		} else {
			fail++
		}
	}
	t.Logf("Debian dpkg corpus: %d/%d cases pass", pass, pass+fail)
}

// TestBackportIsNewerThanUpstream is the ADR-014 case, with the real strings this
// session measured off Metasploitable and the pattern behind the backport false
// positive: an installed package carrying a distro revision is NEWER than bare
// upstream, so treating them as equal reports a patched host as vulnerable.
func TestBackportIsNewerThanUpstream(t *testing.T) {
	cases := []struct{ installed, upstream string }{
		{"2.2.8-1ubuntu0.22", "2.2.8"},   // the S26 example
		{"1.1.1f-1ubuntu2.16", "1.1.1f"}, // ADR-014's own openssl example
	}
	for _, c := range cases {
		if got := CompareDpkg(c.installed, c.upstream); got != 1 {
			t.Errorf("CompareDpkg(%q, %q) = %d, want 1 — a backport revision must sort ABOVE bare upstream, "+
				"or advisory matching reports the patched host as vulnerable (ADR-014)", c.installed, c.upstream, got)
		}
	}
}

func TestCompareDpkg(t *testing.T) {
	for _, c := range dpkgOrderings {
		if got := CompareDpkg(c.a, c.b); got != c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// The reverse must give the opposite sign — a comparator right one way and
		// wrong the other is exactly the silent-false-negative shape.
		if got := CompareDpkg(c.b, c.a); got != -c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d (reverse of the labelled case)", c.b, c.a, got, -c.want)
		}
		// Reflexive.
		if got := CompareDpkg(c.a, c.a); got != 0 {
			t.Errorf("CompareDpkg(%q, %q) = %d, want 0 (reflexive)", c.a, c.a, got)
		}
	}
}
