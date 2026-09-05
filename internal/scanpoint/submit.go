package scanpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// ============================================================================
// The buffer is bounded, and a full buffer refuses work rather than dropping it.
// ============================================================================
//
// ADR-026 is unambiguous: results are always persisted and submitted, nothing is
// discarded. A bounded buffer has to answer what happens at the bound, and there
// are only two answers — drop the oldest, or stop producing more. Dropping is
// the thing the ADR exists to prevent, so this stops producing: at HARD the
// runtime tells Core to assign nothing (Backpressure is the only half of ADR-026
// flow control that can stop the buffer growing) and refuses any assignment that
// arrives anyway.
//
// That makes a saturated scan point stop scanning, which is the correct
// behaviour and is meant to be visible. A scan point that quietly shed
// observations would report clean runs over partial coverage, and under-scanning
// that looks like a clean run is the worst failure this system has, because the
// customer acts on it.
//
// ADR-026 also requires local ENCRYPTED durability, so a scan point that
// finishes a two-hour job and cannot reach Core keeps the results. That is NOT
// implemented: the buffer is memory-only and a restart loses it. Deferred
// deliberately rather than done badly — the only key custody available on a scan
// point today is a key file next to the ciphertext, which protects a stolen
// backup and nothing else, and shipping that would let the ADR read as satisfied.
// Recorded in docs/execution-plan.md §6.5 with what unblocks it.
const (
	// BufferSoftBytes is where the runtime asks Core to slow down.
	BufferSoftBytes = 16 << 20

	// BufferHardBytes is where it stops accepting work.
	//
	// Far below ADR-026's 500 MB, and necessarily: that figure is for the
	// on-disk buffer, while this one lives inside a process with a 512 MB RSS
	// ceiling (execution-plan §5) that is also holding job state, TLS buffers
	// and an engine's output. A 500 MB memory buffer would breach the ceiling
	// long before it filled. When the disk buffer lands, this becomes the
	// spill threshold rather than the limit.
	BufferHardBytes = 64 << 20

	// MaxObservationsPerChunk stays under Core's own per-chunk cap.
	MaxObservationsPerChunk = 2000

	// TargetChunkBytes keeps a chunk well under the 4 MB wire cap
	// (execution-plan §5), leaving room for the framing Core adds.
	TargetChunkBytes = 1 << 20
)

// ErrBufferFull means the runtime cannot take responsibility for more results.
var ErrBufferFull = errors.New("scanpoint: result buffer is full; refusing work")

// Submission is one job's results, ready to upload.
type Submission struct {
	SubmissionID string
	JobID        string
	LeaseEpoch   int64
	Incomplete   bool
	Reason       scanpointv1.TerminationReason
	Observations []*scanpointv1.Observation

	// bytes is an approximation used for the bound. Exactness is not the point:
	// the bound exists to stop unbounded growth, and a payload-length sum is
	// within a small factor of what the process actually holds.
	bytes int

	// resumeFrom is the last chunk Core acknowledged, so a retry after a
	// connection loss resumes rather than restarting (ADR-026).
	resumeFrom uint32
	hasResume  bool
}

// Submitter owns the buffer and the Ingest connection.
type Submitter struct {
	log   *slog.Logger
	dial  func(ctx context.Context) (scanpointv1.IngestClient, func() error, error)
	nowFn func() time.Time

	mu       sync.Mutex
	queue    []*Submission
	buffered int
	wake     chan struct{}
}

func NewSubmitter(log *slog.Logger, dial func(ctx context.Context) (scanpointv1.IngestClient, func() error, error)) *Submitter {
	return &Submitter{
		log:   log,
		dial:  dial,
		nowFn: time.Now,
		wake:  make(chan struct{}, 1),
	}
}

// Pressure is what the Backpressure message carries, and what gates accepting a
// new job.
func (s *Submitter) Pressure() scanpointv1.BackpressureState {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.buffered >= BufferHardBytes:
		return scanpointv1.BackpressureState_BACKPRESSURE_STATE_HARD
	case s.buffered >= BufferSoftBytes:
		return scanpointv1.BackpressureState_BACKPRESSURE_STATE_SOFT
	default:
		return scanpointv1.BackpressureState_BACKPRESSURE_STATE_OK
	}
}

// Buffered reports the current depth, for the heartbeat.
//
// The heartbeat is the only always-flowing channel, so it is the only place Core
// can see a scan point approaching its ceiling rather than learning about it
// after data starts being shed (dispatch.proto).
func (s *Submitter) Buffered() (count int, bytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// buffered is an accumulator that drop() decrements. It is clamped at zero
	// there, and clamped again here: a negative int converted to uint64 becomes
	// roughly eighteen quintillion, and this number is what Core reads on the
	// heartbeat to decide whether a scan point is approaching its ceiling.
	if s.buffered < 0 {
		return len(s.queue), 0
	}
	return len(s.queue), uint64(s.buffered)
}

// Enqueue takes responsibility for a submission, or refuses.
//
// Refusing is the whole design: the caller must not have produced these results
// if the buffer could not hold them, which is why Pressure() gates job
// acceptance upstream of here. A refusal at this point means the bound was
// crossed while the job ran, and it is reported rather than absorbed.
func (s *Submitter) Enqueue(sub *Submission) error {
	for _, o := range sub.Observations {
		sub.bytes += len(o.GetPayload()) + len(o.GetObservationId()) + len(o.GetTaskId()) + 64
	}

	s.mu.Lock()
	if s.buffered+sub.bytes > BufferHardBytes && len(s.queue) > 0 {
		s.mu.Unlock()
		return fmt.Errorf("%w: %d bytes buffered, %d more offered",
			ErrBufferFull, s.buffered, sub.bytes)
	}
	s.queue = append(s.queue, sub)
	s.buffered += sub.bytes
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run drains the queue until ctx is cancelled.
func (s *Submitter) Run(ctx context.Context) {
	backoff := ReconnectMin
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-time.After(backoff):
		}

		sub := s.head()
		if sub == nil {
			backoff = ReconnectMin
			continue
		}

		keep, err := s.deliver(ctx, sub)
		if err != nil && ctx.Err() != nil {
			return
		}
		if keep {
			// RETRY_LATER or a transport failure. The buffer survives, which is
			// the difference between the two rejected statuses and this one:
			// only REJECTED_DUPLICATE and REJECTED_MALFORMED clear without the
			// data having been kept somewhere (ADR-026).
			backoff = min(backoff*2, ReconnectMax)
			continue
		}
		s.drop(sub)
		backoff = ReconnectMin
	}
}

func (s *Submitter) head() *Submission {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return nil
	}
	return s.queue[0]
}

func (s *Submitter) drop(sub *Submission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, q := range s.queue {
		if q == sub {
			s.queue = append(s.queue[:i], s.queue[i+1:]...)
			s.buffered -= sub.bytes
			if s.buffered < 0 {
				s.buffered = 0
			}
			return
		}
	}
}

// deliver uploads one submission. It reports whether to KEEP the buffer.
func (s *Submitter) deliver(ctx context.Context, sub *Submission) (keep bool, err error) {
	client, closeConn, err := s.dial(ctx)
	if err != nil {
		s.log.Warn("ingest unreachable; keeping the buffer",
			slog.String("submission_id", sub.SubmissionID), slog.Any("error", err))
		return true, err
	}
	defer func() { _ = closeConn() }()

	stream, err := client.SubmitResults(ctx)
	if err != nil {
		return true, err
	}

	chunks := chunk(sub)
	for i, c := range chunks {
		idx := u32(i)
		if sub.hasResume && idx <= sub.resumeFrom {
			// Already accepted on a previous attempt. Resumption is the reason
			// SubmitResults is bidirectional: a terminal-only ack could not
			// express a resumption point (ADR-026).
			continue
		}

		if err := stream.Send(&scanpointv1.ResultChunk{
			SubmissionId: sub.SubmissionID,
			JobId:        sub.JobID,
			LeaseEpoch:   sub.LeaseEpoch,
			ChunkIndex:   idx,
			Final:        i == len(chunks)-1,
			Observations: c,
			// On EVERY chunk, not only the last. With resumption Core may
			// process chunks before it ever sees final, and a flag that
			// arrives last cannot stop the finding pipeline from having
			// already run (ingest.proto).
			Incomplete:        sub.Incomplete,
			TerminationReason: sub.Reason,
		}); err != nil {
			return true, err
		}

		ack, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return true, nil
			}
			return true, err
		}

		if ms := ack.GetRetryAfterMs(); ms > 0 {
			// Core-initiated backpressure, arriving while the upload is still
			// running. Honoured mid-stream, because a saturation signal
			// obeyed only at the end has applied no backpressure to the upload
			// it was about.
			select {
			case <-ctx.Done():
				return true, ctx.Err()
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
		}

		switch ack.GetStatus() {
		case scanpointv1.SubmitStatus_ACCEPTED:
			// This chunk is committed, so advance the resumption point — and ONLY
			// here. LastChunkAccepted is a uint32 whose proto3 default is 0, which
			// collides with "chunk 0": Core leaves it unset on a RETRY_LATER when
			// nothing was committed (ingest.go only sets it once hasAccepted), so
			// advancing it on a non-ACCEPTED ack would read that default 0 as
			// "chunk 0 accepted", skip chunk 0 on the retry, and drop a
			// single-chunk submission — results lost, the ADR-026 failure. The
			// scan point already tracks resumeFrom from the ACCEPTED acks it has
			// seen, so a RETRY_LATER needs to move nothing. Guarded by
			// TestSustainedRejectionKeepsTheBufferThenDelivers.
			if ack.GetLastChunkAccepted() >= idx {
				sub.resumeFrom = ack.GetLastChunkAccepted()
				sub.hasResume = true
			}
			// Keep going; the terminal ack decides.
		case scanpointv1.SubmitStatus_ACCEPTED_QUARANTINED:
			// Stored, withheld from the finding pipeline, surfaced to an
			// operator. Stop retrying and clear — retrying would not change
			// the verdict, and the data is already kept.
			s.log.Warn("submission quarantined by Core",
				slog.String("submission_id", sub.SubmissionID),
				slog.String("detail", ack.GetDetail()))
			_ = stream.CloseSend()
			return false, nil
		case scanpointv1.SubmitStatus_REJECTED_DUPLICATE:
			s.log.Info("submission already ingested; clearing",
				slog.String("submission_id", sub.SubmissionID))
			_ = stream.CloseSend()
			return false, nil
		case scanpointv1.SubmitStatus_REJECTED_MALFORMED:
			// Clear, do not retry, log locally. Retrying a payload Core cannot
			// parse is an infinite loop, which is exactly why this status is
			// distinct from RETRY_LATER.
			s.log.Error("submission rejected as malformed; clearing and not retrying",
				slog.String("submission_id", sub.SubmissionID),
				slog.String("detail", ack.GetDetail()))
			_ = stream.CloseSend()
			return false, nil
		case scanpointv1.SubmitStatus_RETRY_LATER:
			s.log.Warn("Core asked for a retry; keeping the buffer",
				slog.String("submission_id", sub.SubmissionID))
			_ = stream.CloseSend()
			return true, nil
		default:
			return true, fmt.Errorf("scanpoint: unknown submit status %v", ack.GetStatus())
		}
	}

	if err := stream.CloseSend(); err != nil {
		return true, err
	}
	// Drain any trailing acks so the terminal one is seen. Core promotes the
	// submission on the final chunk, and a client that hung up early would
	// leave it pending forever.
	for {
		ack, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return true, err
		}
		switch ack.GetStatus() {
		case scanpointv1.SubmitStatus_RETRY_LATER:
			return true, nil
		case scanpointv1.SubmitStatus_ACCEPTED,
			scanpointv1.SubmitStatus_ACCEPTED_QUARANTINED,
			scanpointv1.SubmitStatus_REJECTED_DUPLICATE,
			scanpointv1.SubmitStatus_REJECTED_MALFORMED:
			return false, nil
		}
	}
}

// chunk splits observations by count and approximate size.
func chunk(sub *Submission) [][]*scanpointv1.Observation {
	if len(sub.Observations) == 0 {
		// One empty final chunk. A job that produced nothing still has to say
		// so: the submission_id is the join between "terminal seen" and
		// "results arrived", and a job with no chunk at all is
		// indistinguishable from one still uploading.
		return [][]*scanpointv1.Observation{nil}
	}

	var out [][]*scanpointv1.Observation
	var cur []*scanpointv1.Observation
	size := 0
	for _, o := range sub.Observations {
		n := len(o.GetPayload()) + 128
		if len(cur) > 0 && (len(cur) >= MaxObservationsPerChunk || size+n > TargetChunkBytes) {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, o)
		size += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
