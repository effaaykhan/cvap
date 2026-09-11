package version

import "testing"

// The B26 regression: full RPM epoch:version-release strings must compare via the EVR
// rules (epoch numeric first, then rpmvercmp on version and release), not by handing
// the whole string to rpmvercmp — which compared the epoch digit against the first
// version segment and made a fully-patched host read as vulnerable to an epoch-less
// advisory fix.
func TestCompareRPMEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// The exact false-positive case: installed (epoch 0 explicit) vs ALSA fix
		// (no epoch). Must be EQUAL, so a fully-patched package is not flagged.
		{"0:9.9p1-25.el10_2.alma.1", "9.9p1-25.el10_2.alma.1", 0},
		// One release behind -> installed < fixed.
		{"0:2.4.63-13.el10_2", "2.4.63-13.el10_2.1", -1},
		// Epoch dominates the version (rpm rule): a higher epoch outranks a higher
		// version, and vice versa.
		{"2:3.8.5-10.el10_2", "3:1.0-1.el10", -1},
		{"2:3.8.5-10.el10_2", "1:99.0-1.el10", 1},
	}
	for _, c := range cases {
		if got := Compare(SchemeRPM, c.a, c.b); got != c.want {
			t.Errorf("Compare(RPM, %q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
