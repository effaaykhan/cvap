package load

import "testing"

// The coarse/precise gate split is the load test's contract with CI: CI enforces
// the coarse ceiling, the precise SLO runs locally and nightly. That split is
// only meaningful if each half fires on its own — a coarse ceiling that never
// fails is not a ceiling, and a precise SLO that fires in CI is the flake the
// split exists to avoid. These cases prove each half independently, DB-free, so
// they run everywhere the coarse gate does.

// mutate:subject test/load/load_test.go
// mutate:test    ./test/load/ -run TestGateHalvesFireIndependently
//
// mutate:case    the coarse ceiling is lifted so it never fires
// mutate:old     coarseMs := 2 * sloMs
// mutate:new     coarseMs := 2000 * sloMs
//
// mutate:case    the precise SLO comparison is disabled
// mutate:old     if precise && measuredMs > float64(sloMs) {
// mutate:new     if precise && measuredMs > float64(sloMs)*2000 {
//
// The two mutations hit the two halves of checkLatency. The first lifts the
// coarse ceiling out of reach — killed only by a coarse-breach case, and NOT by
// any precise case, because a precise breach within the (now absurd) coarse
// bound still reports preciseFailed. The second neutralises the precise
// comparison — killed only by a precise-breach case that is within the coarse
// bound. Neither mutation is caught by the other's case, which is what "sabotaged
// independently" means.

func TestGateHalvesFireIndependently(t *testing.T) {
	const slo = 500 // ms; coarse ceiling is 1000

	latency := []struct {
		name        string
		measured    float64
		precise     bool
		wantCoarse  bool
		wantPrecise bool
	}{
		// Coarse half. A breach fails in CI (precise=false) AND locally.
		{"coarse breach, CI", 1200, false, true, false},
		{"coarse breach, local", 1200, true, true, false},
		// Precise half. A breach within the coarse ceiling is silent in CI and
		// fails only locally — the whole reason for the split.
		{"precise breach, CI silent", 700, false, false, false},
		{"precise breach, local fails", 700, true, false, true},
		// Comfortably inside: never fires.
		{"within SLO, CI", 40, false, false, false},
		{"within SLO, local", 40, true, false, false},
		// Exactly at the SLO is not a breach (the comparison is strictly >).
		{"at the SLO, local", 500, true, false, false},
	}
	for _, c := range latency {
		v := checkLatency(c.measured, slo, c.precise)
		if v.coarseFailed != c.wantCoarse || v.preciseFailed != c.wantPrecise {
			t.Errorf("checkLatency(%.0f, %d, precise=%v) = %+v; want coarse=%v precise=%v",
				c.measured, slo, c.precise, v, c.wantCoarse, c.wantPrecise)
		}
	}

	// The throughput gate mirrors the logic as a floor; a smoke case each way so
	// a regression in it is not invisible.
	const tput = 5000 // ops/sec; coarse floor is 2500
	if v := checkThroughput(2000, tput, false); !v.coarseFailed {
		t.Error("checkThroughput: 2000/sec should breach the coarse floor even in CI")
	}
	if v := checkThroughput(4000, tput, true); !v.preciseFailed {
		t.Error("checkThroughput: 4000/sec should breach the precise SLO locally")
	}
	if v := checkThroughput(4000, tput, false); v.coarseFailed || v.preciseFailed {
		t.Error("checkThroughput: 4000/sec is above the coarse floor and must be silent in CI")
	}
}
