package domain

import (
	"testing"
	"time"
)

func TestMedianGap(t *testing.T) {
	h := func(n int) time.Time { return time.Date(2026, 9, 1, n, 0, 0, 0, time.UTC) }
	if _, ok := MedianGap(nil); ok {
		t.Error("no instants: want unmeasured")
	}
	if _, ok := MedianGap([]time.Time{h(1)}); ok {
		t.Error("one instant: want unmeasured")
	}
	// Unsorted input, odd gap count: 2h, 2h, 20h -> median 2h.
	if g, ok := MedianGap([]time.Time{h(4), h(0), h(2), h(24)}); !ok || g != 2*time.Hour {
		t.Errorf("median of gaps {2h,2h,20h} = %s, want 2h", g)
	}
	// Even gap count: 1h, 3h -> 2h.
	if g, _ := MedianGap([]time.Time{h(0), h(1), h(4)}); g != 2*time.Hour {
		t.Errorf("median of gaps {1h,3h} = %s, want 2h", g)
	}
}
