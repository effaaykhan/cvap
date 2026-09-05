package scanpoint

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// ============================================================================
// F6×F5 — sustained rejection keeps the buffer, and nothing is lost.
// ============================================================================
//
// F6 proves Core rejects work under saturation (HARD assigns nothing; RETRY_LATER
// refuses a submission). F5 proves the buffer survives a dropped stream. Each
// passes alone, but the property an operator actually depends on lives in their
// COMPOSITION: a Core that rejects for a sustained stretch must leave the scan
// point holding a full buffer and, on recovery, deliver every observation — not a
// scan point that gave up and dropped results (the failure ADR-026 exists to
// prevent). A gap between two green cases is still a gap.
//
// This drives the real Run loop against a Core that answers RETRY_LATER twice
// before it recovers. RETRY_LATER is the flow-control response to saturation —
// "keep the buffer, back off" (ingest.proto) — so it is the sustained-rejection
// signal in its exact wire form. The assertion is on WORK preserved: the one
// observation enqueued is delivered exactly once, after the rejections, and the
// buffer drains to empty.
//
// The seam is Run's `if keep`: only REJECTED_DUPLICATE/REJECTED_MALFORMED clear
// the buffer; RETRY_LATER and transport failures keep it. The sabotage makes Run
// drop on every result, so the first rejection loses the buffer and the
// observation never arrives — the compose fails even though F5 and F6 still pass.
//
// mutate:subject internal/scanpoint/submit.go
// mutate:test    ./internal/scanpoint/ -run TestSustainedRejectionKeepsTheBufferThenDelivers
//
// mutate:case    a rejection drops the buffer instead of keeping it
// mutate:old     		if keep {
// mutate:new     		if !keep {
func TestSustainedRejectionKeepsTheBufferThenDelivers(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	fc := &retryingIngestClient{rejectFirst: 2}
	s := NewSubmitter(discard, func(ctx context.Context) (scanpointv1.IngestClient, func() error, error) {
		return fc, func() error { return nil }, nil
	})

	sub := &Submission{
		SubmissionID: "sub", JobID: "job", LeaseEpoch: 1,
		Observations: []*scanpointv1.Observation{{ObservationId: "obs-1", TaskId: "t"}},
	}
	if err := s.Enqueue(sub); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	// The buffer must survive the rejections and drain ONLY by delivering. The
	// moment it empties, it must have delivered — an empty buffer with nothing
	// delivered is the drop-and-lose failure, and catching it there fails fast
	// rather than waiting out the deadline. Give the backoff (1s then 2s) room.
	deadline := time.Now().Add(15 * time.Second)
	for {
		count, _ := s.Buffered()
		if count == 0 {
			if fc.deliveredCount() > 0 {
				break // delivered, then drained — the correct path
			}
			t.Fatalf("the buffer emptied without delivering anything (delivered=%d); a "+
				"sustained rejection dropped the buffer instead of holding it, and the results "+
				"are lost (ADR-026)", fc.deliveredCount())
		}
		if time.Now().After(deadline) {
			t.Fatalf("buffer never drained (buffered=%d, delivered=%d)", count, fc.deliveredCount())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Delivered exactly once, and it is the observation that was enqueued — no
	// loss, no phantom.
	got := fc.delivered()
	if len(got) != 1 || got[0] != "obs-1" {
		t.Fatalf("delivered observations = %v, want exactly [obs-1]", got)
	}
	// And it took more than one attempt to get there — the rejections really
	// happened, so the buffer really was held across them.
	if fc.attempts() < 3 {
		t.Errorf("delivery took %d attempts, want >= 3 (two rejections then success); the "+
			"rejection path was not exercised", fc.attempts())
	}
}

// retryingIngestClient answers RETRY_LATER for the first rejectFirst upload
// attempts, then ACCEPTED, recording the observation ids it accepts.
type retryingIngestClient struct {
	rejectFirst int

	mu      sync.Mutex
	attempt int
	got     []string
}

func (f *retryingIngestClient) attempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempt
}
func (f *retryingIngestClient) delivered() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}
func (f *retryingIngestClient) deliveredCount() int { return len(f.delivered()) }

func (f *retryingIngestClient) SubmitResults(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[scanpointv1.ResultChunk, scanpointv1.SubmitAck], error) {
	f.mu.Lock()
	f.attempt++
	reject := f.attempt <= f.rejectFirst
	f.mu.Unlock()
	return &retryingBidi{client: f, reject: reject, ctx: ctx}, nil
}

type retryingBidi struct {
	client *retryingIngestClient
	reject bool
	ctx    context.Context
	last   *scanpointv1.ResultChunk
	closed bool
}

func (b *retryingBidi) Send(c *scanpointv1.ResultChunk) error { b.last = c; return nil }

func (b *retryingBidi) Recv() (*scanpointv1.SubmitAck, error) {
	if b.closed || b.last == nil {
		return nil, io.EOF
	}
	c := b.last
	b.last = nil
	if b.reject {
		return &scanpointv1.SubmitAck{
			SubmissionId: c.GetSubmissionId(),
			Status:       scanpointv1.SubmitStatus_RETRY_LATER,
		}, nil
	}
	b.client.mu.Lock()
	for _, o := range c.GetObservations() {
		b.client.got = append(b.client.got, o.GetObservationId())
	}
	b.client.mu.Unlock()
	return &scanpointv1.SubmitAck{
		SubmissionId:      c.GetSubmissionId(),
		LastChunkAccepted: c.GetChunkIndex(),
		Status:            scanpointv1.SubmitStatus_ACCEPTED,
	}, nil
}

func (b *retryingBidi) CloseSend() error             { b.closed = true; return nil }
func (b *retryingBidi) Context() context.Context     { return b.ctx }
func (b *retryingBidi) Header() (metadata.MD, error) { return nil, nil }
func (b *retryingBidi) Trailer() metadata.MD         { return nil }
func (b *retryingBidi) SendMsg(any) error            { return nil }
func (b *retryingBidi) RecvMsg(any) error            { return nil }
