package scanpoint

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// ============================================================================
// F6a — the buffer reports HARD at its ceiling and then refuses work.
// ============================================================================
//
// Backpressure is the only thing that stops a scan point queueing results
// unboundedly inside a customer's network (ADR-026). Its state was covered only
// at the wire-contract level — that the enum has an unspecified zero — and never
// by filling the buffer and reading what Pressure() reports. This does that: it
// drives a real Submitter's byte accumulator across the thresholds and asserts
// SOFT at the soft mark, HARD at the ceiling, and that Enqueue then REFUSES with
// ErrBufferFull rather than growing further.
//
// The refusal is the design: the first submission is always taken (the buffer
// can be empty and the job already ran), but once it is full the next is refused
// and reported, not absorbed. The complementary half — Core assigning nothing on
// a HARD signal — is F6b, in the dispatch package.
//
// mutate:subject internal/scanpoint/submit.go
// mutate:test    ./internal/scanpoint/ -run TestBufferSaturationReportsHardThenRefuses
//
// mutate:case    the buffer never reports HARD, so Core is never told to stop
// mutate:old     	case s.buffered >= BufferHardBytes:
// mutate:new     	case false:
func TestBufferSaturationReportsHardThenRefuses(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	// SOFT: a fresh buffer, filled just past the soft mark but below the ceiling.
	soft := NewSubmitter(discard, nil)
	if got := soft.Pressure(); got != scanpointv1.BackpressureState_BACKPRESSURE_STATE_OK {
		t.Fatalf("empty buffer Pressure() = %v, want OK", got)
	}
	if err := soft.Enqueue(submissionOfBytes(BufferSoftBytes + (1 << 20))); err != nil {
		t.Fatalf("first enqueue refused: %v", err)
	}
	if got := soft.Pressure(); got != scanpointv1.BackpressureState_BACKPRESSURE_STATE_SOFT {
		t.Errorf("buffer past the soft mark Pressure() = %v, want SOFT", got)
	}

	// HARD: a fresh buffer taken to the ceiling in one submission (the first is
	// always accepted, whatever its size), then a second submission refused.
	hard := NewSubmitter(discard, nil)
	if err := hard.Enqueue(submissionOfBytes(BufferHardBytes + (1 << 20))); err != nil {
		t.Fatalf("first (large) enqueue refused: %v", err)
	}
	if got := hard.Pressure(); got != scanpointv1.BackpressureState_BACKPRESSURE_STATE_HARD {
		t.Fatalf("buffer at the ceiling Pressure() = %v, want HARD; Core is never told to "+
			"stop assigning and the buffer grows unbounded inside the customer network", got)
	}
	if err := hard.Enqueue(submissionOfBytes(1 << 20)); !errors.Is(err, ErrBufferFull) {
		t.Fatalf("enqueue past the ceiling returned %v, want ErrBufferFull; a full buffer "+
			"must refuse and report, not absorb (ADR-026)", err)
	}
}

// submissionOfBytes builds a submission whose approximate buffered size is at
// least n, via a single observation payload. Enqueue sums payload lengths plus a
// small per-observation overhead, so a payload of n is at least n.
func submissionOfBytes(n int) *Submission {
	return &Submission{
		SubmissionID: "sub",
		JobID:        "job",
		Observations: []*scanpointv1.Observation{
			{ObservationId: "o", TaskId: "t", Payload: make([]byte, n)},
		},
	}
}
