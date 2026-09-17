package domain

import (
	"sort"
	"time"
)

// MedianGap is the median interval between consecutive instants — the scan
// cadence the sighting window has to accommodate (ADR-100). ok is false with
// fewer than two instants, so the caller can say "unmeasured" rather than 0.
func MedianGap(at []time.Time) (time.Duration, bool) {
	if len(at) < 2 {
		return 0, false
	}
	ts := append([]time.Time(nil), at...)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	gaps := make([]time.Duration, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i].Sub(ts[i-1]))
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	if n := len(gaps); n%2 == 1 {
		return gaps[n/2], true
	} else {
		return (gaps[n/2-1] + gaps[n/2]) / 2, true
	}
}
