package load

import (
	"testing"
	"time"
)

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

// The per-measurement budget is what stops one slow path from spending the whole
// run and silencing the measurements after it (B47, ADR-098). Two things must
// hold for that to be a fact: a measurement that overruns its budget stops and
// SAYS it was truncated, carrying the p95 of what it completed; and one inside
// its budget completes the full sample untouched. DB-free, so it runs everywhere
// the coarse gate does.
func TestMeasurementBudgetTruncatesAndSaysSo(t *testing.T) {
	// Slow path: every request takes 2 ms against a 20 ms budget.
	slow := sampleP95(func() float64 { time.Sleep(2 * time.Millisecond); return 2 }, 20*time.Millisecond)
	if !slow.truncated {
		t.Fatalf("a measurement that cannot finish inside its budget must report truncated: %+v", slow)
	}
	if slow.completed >= sampleRequests {
		t.Errorf("truncated measurement completed the full sample: %+v", slow)
	}

	// Inside the budget: the full sample, warmup discarded, p95 of the sample.
	i := 0
	fast := sampleP95(func() float64 { i++; return float64(i) }, time.Hour)
	if fast.truncated || fast.completed != sampleRequests {
		t.Fatalf("a measurement inside its budget must complete the whole sample: %+v", fast)
	}
	// Latencies 21..320 after the 20-request warmup; p95 index 285 -> 306.
	if want := float64(warmupRequests + int(0.95*float64(sampleRequests)) + 1); fast.p95ms != want {
		t.Errorf("p95 of the sample = %.0f, want %.0f", fast.p95ms, want)
	}

	// A measurement truncated before any sample completed has no number to
	// report, and says 0 completed rather than inventing one.
	none := sampleP95(func() float64 { time.Sleep(5 * time.Millisecond); return 5 }, 0)
	if !none.truncated || none.completed != 0 || none.p95ms != 0 {
		t.Errorf("truncated-in-warmup measurement should carry no sample: %+v", none)
	}

	// The budget is every request at the coarse ceiling: 320 x 1000 ms for the
	// finding list.
	if got := measurementBudget(2 * findingListSLOms); got != 320*time.Second {
		t.Errorf("measurementBudget(1000ms) = %s, want 320s", got)
	}
}
