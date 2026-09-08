package version

import "testing"

// The comparators must be a TOTAL ORDER (up to equality): antisymmetric,
// transitive, and returning a value in {-1,0,+1} for every pair. ADR-059 P3.1
// asks for this because a comparator that says a<b and b<a — or a<b<c but a>c —
// is worse than one that errors: it makes matching's answer depend on iteration
// order, which is the silent, unreproducible kind of wrong. Checked exhaustively
// over a pool per scheme, including the tricky epoch/tilde/caret/backport strings.
func TestComparatorProperties(t *testing.T) {
	pools := map[Scheme][]string{
		SchemeDpkg: {
			"0", "1.0", "1.0-1", "1.0-2", "1:1.0", "1.0~rc1", "1.0~rc2",
			"2.0", "1.0.1", "1.00", "2.2.8", "2.2.8-1ubuntu0.22", "1a",
		},
		SchemeRPM: {
			"1.0", "2.0", "2.0.1", "5.5p1", "5.5p10", "1.0~rc1", "1.0^git1",
			"1.0^", "xyz.4", "8", "10xyz", "10.1xyz",
		},
	}
	names := map[Scheme]string{SchemeDpkg: "dpkg", SchemeRPM: "rpm"}

	for s, pool := range pools {
		name := names[s]
		for _, a := range pool {
			for _, b := range pool {
				ab := Compare(s, a, b)
				ba := Compare(s, b, a)

				// Total: the result is always a sign.
				if ab < -1 || ab > 1 {
					t.Fatalf("%s: Compare(%q,%q)=%d is not in {-1,0,1}", name, a, b, ab)
				}
				// Antisymmetric: swapping the arguments negates the result.
				if ab != -ba {
					t.Errorf("%s: not antisymmetric — Compare(%q,%q)=%d but Compare(%q,%q)=%d",
						name, a, b, ab, b, a, ba)
				}

				for _, c := range pool {
					bc := Compare(s, b, c)
					ac := Compare(s, a, c)
					// Transitive for <=: a<=b and b<=c implies a<=c.
					if ab <= 0 && bc <= 0 && ac > 0 {
						t.Errorf("%s: not transitive — %q<=%q<=%q but Compare(%q,%q)=%d>0",
							name, a, b, c, a, c, ac)
					}
					// Transitive for equality: a==b and b==c implies a==c.
					if ab == 0 && bc == 0 && ac != 0 {
						t.Errorf("%s: equality not transitive — %q==%q==%q but Compare(%q,%q)=%d",
							name, a, b, c, a, c, ac)
					}
				}
			}
		}
	}
}

// TestOperatorsAndRange exercises the advisory-facing surface: the <, >=
// operators and the range form, including that a backport revision clears a fix
// expressed at that same revision.
func TestOperatorsAndRange(t *testing.T) {
	if !Satisfies(SchemeDpkg, "1.0", OpLT, "1.0-1") {
		t.Error("1.0 < 1.0-1 should hold")
	}
	if !Satisfies(SchemeDpkg, "2.2.8-1ubuntu0.22", OpGE, "2.2.8") {
		t.Error("a backport revision should be >= bare upstream")
	}
	if !Satisfies(SchemeRPM, "5.5p1", OpLT, "5.5p10") {
		t.Error("rpm: 5.5p1 < 5.5p10 (numeric, not lexical)")
	}

	// Affected < 1.1.1f-1ubuntu2.16; a host patched to exactly that is cleared.
	r := AffectedRange{Fixed: "1.1.1f-1ubuntu2.16"}
	if !r.Vulnerable(SchemeDpkg, "1.1.1f-1ubuntu2.10") {
		t.Error("an older revision than the fix must be vulnerable")
	}
	if r.Vulnerable(SchemeDpkg, "1.1.1f-1ubuntu2.16") {
		t.Error("the exact fixed revision must NOT be vulnerable — the backport false-positive guard")
	}
	if r.Vulnerable(SchemeDpkg, "1.1.1f-1ubuntu2.17") {
		t.Error("a newer revision than the fix must NOT be vulnerable")
	}
}
