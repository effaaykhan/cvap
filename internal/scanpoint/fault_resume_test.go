package scanpoint

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// ============================================================================
// F5 — a resumed upload restarts from the last acked chunk, not from zero.
// ============================================================================
//
// The question stated before running it (session 20, note 3): a submission whose
// stream drops after chunks 0–2 are accepted — on the retry, does the scan point
// resend from 0 or from 3, and is last_chunk_accepted authoritative or advisory?
//
// The answer this pins: AUTHORITATIVE. deliver() skips every chunk index <=
// resumeFrom, and resumeFrom is set from the SubmitAck.last_chunk_accepted of the
// previous attempt (submit.go). So the retry resends from 3, and the per-chunk
// ack is load-bearing, not decorative — which is why SubmitResults is
// bidirectional at all (ADR-026): a terminal-only ack could not carry a
// resumption point. If the runtime resent from 0 and relied on Core dedup, the
// ack would be decorative and a large submission would re-upload in full on every
// blip; this asserts it does not.
//
// Scope note: this is the RESUMPTION path within a live process, driven at the
// Submitter seam where -overlay applies. A full process RESTART is different —
// the buffer is memory-only and a restart loses it outright (encrypted local
// durability is deferred, submit.go / execution-plan §6.5). That is a documented
// limitation, not a resumption; it has no in-process seam to sabotage and is not
// asserted here (ADR-056).
//
// mutate:subject internal/scanpoint/submit.go
// mutate:test    ./internal/scanpoint/ -run TestResumeRestartsFromLastAckedChunk
//
// mutate:case    the resume point is ignored, so every retry re-uploads from zero
// mutate:old     		if sub.hasResume && idx <= sub.resumeFrom {
// mutate:new     		if false && idx <= sub.resumeFrom {
func TestResumeRestartsFromLastAckedChunk(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Four chunks: one observation per chunk, each payload over the chunk size
	// so chunk() splits one-to-one and the indices are 0..3.
	sub := &Submission{SubmissionID: "sub", JobID: "job", LeaseEpoch: 1}
	for i := 0; i < 4; i++ {
		sub.Observations = append(sub.Observations, &scanpointv1.Observation{
			ObservationId: "o", TaskId: "t", Payload: make([]byte, TargetChunkBytes+1),
		})
	}

	fc := &fakeIngestClient{dropChunkOnFirstAttempt: 3}
	s := NewSubmitter(discard, func(ctx context.Context) (scanpointv1.IngestClient, func() error, error) {
		return fc, func() error { return nil }, nil
	})
	if err := s.Enqueue(sub); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	ctx := context.Background()

	// Attempt 1: the stream drops when chunk 3 is sent. The buffer is kept, and
	// the resume point is now chunk 2 (the last one acked).
	keep, _ := s.deliver(ctx, sub)
	if !keep {
		t.Fatal("first attempt did not keep the buffer after the stream dropped mid-upload")
	}
	if !sub.hasResume || sub.resumeFrom != 2 {
		t.Fatalf("after chunks 0-2 acked, resumeFrom = %d (hasResume=%v), want 2",
			sub.resumeFrom, sub.hasResume)
	}

	// Attempt 2: it must resend from chunk 3, never re-sending 0-2.
	keep2, err2 := s.deliver(ctx, sub)
	if err2 != nil {
		t.Fatalf("second attempt errored: %v", err2)
	}
	if keep2 {
		t.Error("second attempt kept the buffer; the resumed upload should have completed")
	}

	second := fc.attempts[1]
	if len(second) == 0 {
		t.Fatal("the retry sent no chunks")
	}
	if second[0] != 3 {
		t.Fatalf("the retry's first chunk was %d, want 3; the scan point re-uploaded from an "+
			"earlier point instead of resuming from last_chunk_accepted — the per-chunk ack is "+
			"decorative if this fails", second[0])
	}
	for _, idx := range second {
		if idx < 3 {
			t.Errorf("the retry re-sent chunk %d, which Core had already accepted", idx)
		}
	}
}

// fakeIngestClient is a minimal in-process IngestClient. Each SubmitResults call
// is a new stream (a new upload attempt); the client records the chunk indices
// sent on each attempt and, on the first attempt, drops the connection when the
// configured chunk is sent.
type fakeIngestClient struct {
	dropChunkOnFirstAttempt uint32
	attempt                 int
	attempts                [][]uint32
}

func (f *fakeIngestClient) SubmitResults(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[scanpointv1.ResultChunk, scanpointv1.SubmitAck], error) {
	f.attempt++
	f.attempts = append(f.attempts, nil)
	return &fakeBidi{client: f, attempt: f.attempt, ctx: ctx}, nil
}

type fakeBidi struct {
	client   *fakeIngestClient
	attempt  int
	ctx      context.Context
	lastIdx  uint32
	haveLast bool
	closed   bool
}

func (b *fakeBidi) Send(c *scanpointv1.ResultChunk) error {
	b.client.attempts[b.attempt-1] = append(b.client.attempts[b.attempt-1], c.GetChunkIndex())
	if b.attempt == 1 && c.GetChunkIndex() >= b.client.dropChunkOnFirstAttempt {
		return errors.New("fake ingest: connection dropped mid-upload")
	}
	b.lastIdx, b.haveLast = c.GetChunkIndex(), true
	return nil
}

func (b *fakeBidi) Recv() (*scanpointv1.SubmitAck, error) {
	if b.closed || !b.haveLast {
		return nil, io.EOF
	}
	b.haveLast = false
	return &scanpointv1.SubmitAck{
		LastChunkAccepted: b.lastIdx,
		Status:            scanpointv1.SubmitStatus_ACCEPTED,
	}, nil
}

func (b *fakeBidi) CloseSend() error             { b.closed = true; return nil }
func (b *fakeBidi) Context() context.Context     { return b.ctx }
func (b *fakeBidi) Header() (metadata.MD, error) { return nil, nil }
func (b *fakeBidi) Trailer() metadata.MD         { return nil }
func (b *fakeBidi) SendMsg(any) error            { return nil }
func (b *fakeBidi) RecvMsg(any) error            { return nil }
