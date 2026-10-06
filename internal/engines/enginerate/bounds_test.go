package enginerate

import (
	"math"
	"testing"
	"time"
)

// TestSynTrainBoundCoversTheMeasuredTrains: the bound sits at or above every SYN
// train measured against the lab's filtered host on a kernel with
// tcp_syn_linear_timeouts=4, including the ones SynCost undercounts.
func TestSynTrainBoundCoversTheMeasuredTrains(t *testing.T) {
	for _, m := range []struct {
		timeout  time.Duration
		measured uint32
	}{
		{500 * time.Millisecond, 1},
		{time.Second, 1},
		{2500 * time.Millisecond, 3}, // SynCost says 2
		{3 * time.Second, 3},
		{3500 * time.Millisecond, 4}, // SynCost says 3
		{7500 * time.Millisecond, 7}, // SynCost says 4
	} {
		if got := SynTrainBound(m.timeout); got < m.measured {
			t.Errorf("SynTrainBound(%v) = %d, below the %d SYNs measured on the wire",
				m.timeout, got, m.measured)
		}
	}
}

// TestSynTrainBoundIsNeverBelowTheModel: a ceiling below the expected cost
// would make admission looser than the pacing it replaces.
func TestSynTrainBoundIsNeverBelowTheModel(t *testing.T) {
	for d := time.Duration(0); d <= 20*time.Second; d += 50 * time.Millisecond {
		if SynTrainBound(d) < SynCost(d) {
			t.Fatalf("SynTrainBound(%v) = %d < SynCost = %d", d, SynTrainBound(d), SynCost(d))
		}
	}
}

func TestConnectionBoundIsTheTrainPlusTheEstablishedPackets(t *testing.T) {
	for _, d := range []time.Duration{0, 500 * time.Millisecond, 3 * time.Second} {
		if got, want := ConnectionBound(d), SynTrainBound(d)+EstablishedCost; got != want {
			t.Errorf("ConnectionBound(%v) = %d, want %d", d, got, want)
		}
	}
}

// TestTheBoundsSaturateRatherThanWrap: at the edge of uint32 every bound holds at
// the maximum. A conversion that wrapped would hand back a SMALL admission for an
// enormous cost — the one direction a ceiling may never err (gosec G115).
func TestTheBoundsSaturateRatherThanWrap(t *testing.T) {
	const maxU = math.MaxUint32
	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		// SynTrainBound: 1 + whole seconds, either side of the edge.
		{"SynTrainBound one below the edge", SynTrainBound((maxU - 2) * time.Second), maxU - 1},
		{"SynTrainBound at the edge", SynTrainBound((maxU - 1) * time.Second), maxU},
		{"SynTrainBound one past the edge", SynTrainBound(maxU * time.Second), maxU},
		{"SynTrainBound at the duration maximum", SynTrainBound(math.MaxInt64), maxU},

		// ConnectionBound adds EstablishedCost to that.
		{"ConnectionBound below the edge", ConnectionBound((maxU - 1 - EstablishedCost - 1) * time.Second), maxU - 1},
		{"ConnectionBound at the duration maximum", ConnectionBound(math.MaxInt64), maxU},

		// Segments: a whole multiple, one byte over it, and the int maximum.
		{"Segments exactly at the edge", Segments(maxU * SegmentPayload), maxU},
		{"Segments one byte past the edge", Segments(maxU*SegmentPayload + 1), maxU},
		{"Segments one below the edge", Segments((maxU - 1) * SegmentPayload), maxU - 1},
		{"Segments at the int maximum", Segments(math.MaxInt), maxU},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestTheBoundsNeverDecreaseAcrossTheEdge: a larger input is never admitted at
// less, including where the conversion would have wrapped.
func TestTheBoundsNeverDecreaseAcrossTheEdge(t *testing.T) {
	edge := time.Duration(math.MaxUint32) * time.Second
	var prev uint32
	for d := edge - 3*time.Second; d <= edge+3*time.Second; d += 500 * time.Millisecond {
		got := SynTrainBound(d)
		if got < prev {
			t.Fatalf("SynTrainBound(%v) = %d, below %d for a shorter duration", d, got, prev)
		}
		prev = got
	}
	prev = 0
	for n := (math.MaxUint32 - 2) * SegmentPayload; n <= (math.MaxUint32+2)*SegmentPayload; n += SegmentPayload / 2 {
		got := Segments(n)
		if got < prev {
			t.Fatalf("Segments(%d) = %d, below %d for fewer bytes", n, got, prev)
		}
		prev = got
	}
}

func TestSegmentsRoundsUp(t *testing.T) {
	for _, c := range []struct {
		n    int
		want uint32
	}{{-1, 0}, {0, 0}, {1, 1}, {SegmentPayload, 1}, {SegmentPayload + 1, 2}, {1505, 3}} {
		if got := Segments(c.n); got != c.want {
			t.Errorf("Segments(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}
