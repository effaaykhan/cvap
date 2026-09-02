package dispatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/store"
)

// Rejections that must roll back their transaction before being turned into an
// ack. Setting the ack inside the callback and returning nil would commit — and
// after a unique violation the transaction is already aborted, so the commit
// fails and the scan point is told RETRY_LATER for something that will never
// succeed.
var (
	errDuplicate = errors.New("ingest: submission_id already ingested")
	errMalformed = errors.New("ingest: malformed chunk")
)

// maxObservationsPerChunk bounds one chunk. The wire cap is 4 MB
// (execution-plan §5); this bounds row count independently, because a chunk of
// tiny observations can be well inside the byte limit and still be a large
// transaction.
const maxObservationsPerChunk = 5000

// IngestService implements scanpointv1.IngestServer.
//
// A separate service from Dispatch, by contract (ADR-005, ADR-026). Folding
// submission into the dispatch stream couples upload progress to dispatch
// liveness — a long upload is then killed by an ordinary reconnect — and makes
// independent scaling impossible. The two have genuinely different load shapes.
type IngestService struct {
	scanpointv1.UnimplementedIngestServer

	db  *store.DB
	log *slog.Logger
	now func() time.Time
}

func NewIngest(db *store.DB, log *slog.Logger) *IngestService {
	return &IngestService{db: db, log: log, now: time.Now}
}

// submission is the per-stream state for one upload.
type submission struct {
	id     string
	jobID  uuid.UUID
	epoch  int64
	chunks int

	// The resumption point, as it travels on the wire. A uint32 with a
	// separate "have we accepted one yet" flag rather than an int32 with -1 as
	// a sentinel: chunk_index is uint32 on the wire, and squeezing it into an
	// int32 wraps negative above MaxInt32. The flag costs a byte and removes
	// two conversions that gosec was right to flag.
	lastAccepted uint32
	hasAccepted  bool

	// quarantined is sticky. Once any chunk fails the epoch check the whole
	// submission is quarantined, and the terminal promotion sends every one of
	// its observations to quarantined together.
	quarantined bool
	reason      string

	// incomplete arrives on EVERY chunk rather than only the final one, because
	// with resumption Core may process chunks before it ever sees final, and a
	// flag that arrives last cannot stop the finding pipeline from having
	// already run. Once true it stays true.
	incomplete bool
}

// SubmitResults receives chunked observations and acknowledges each one.
func (s *IngestService) SubmitResults(stream scanpointv1.Ingest_SubmitResultsServer) error {
	ctx := stream.Context()

	fingerprint, err := enrollment.PeerFingerprint(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, "ingest requires a client certificate")
	}
	tenant, err := s.db.ResolveScanPointTenant(ctx, fingerprint)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotResolved) {
			return status.Error(codes.Unauthenticated, "certificate is not enrolled")
		}
		s.log.ErrorContext(ctx, "ingest tenant resolution failed", slog.Any("error", err))
		return status.Error(codes.Internal, "ingest unavailable")
	}

	var spID uuid.UUID
	if err := s.db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByFingerprint(ctx, c, fingerprint)
		if err != nil {
			return err
		}
		spID = sp.ID
		return nil
	}); err != nil {
		return status.Error(codes.Unauthenticated, "certificate is not enrolled")
	}

	var sub *submission

	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			// The stream ended without a final chunk. The submission stays
			// pending, which is the point of the pending state: nothing
			// half-uploaded reaches the finding pipeline, and the rows remain as
			// the record of what was received (ADR-026).
			if sub != nil {
				s.log.WarnContext(ctx, "submission stream ended without a final chunk",
					slog.String("submission_id", sub.id),
					slog.Int("chunks", sub.chunks))
			}
			return nil
		}
		if err != nil {
			return err
		}

		ack, err := s.handleChunk(ctx, tenant, spID, &sub, chunk)
		if err != nil {
			return err
		}
		if err := stream.Send(ack); err != nil {
			return err
		}
	}
}

// handleChunk is one chunk, one transaction, one ack.
func (s *IngestService) handleChunk(ctx context.Context, tenant store.TenantID, spID uuid.UUID, subp **submission, chunk *scanpointv1.ResultChunk) (*scanpointv1.SubmitAck, error) {
	// NOTE: chunk is never logged or formatted. Observation payloads are
	// customer data and the message is large; logging.Proto is the only path
	// (ADR-034).

	submissionID := chunk.GetSubmissionId()
	if submissionID == "" || len(submissionID) > 200 {
		return malformed(submissionID, "missing or oversized submission_id"), nil
	}
	if len(chunk.GetObservations()) > maxObservationsPerChunk {
		return malformed(submissionID, "too many observations in one chunk"), nil
	}

	jobID, err := uuid.Parse(chunk.GetJobId())
	if err != nil {
		return malformed(submissionID, "malformed job id"), nil
	}

	sub := *subp
	if sub == nil {
		sub = &submission{id: submissionID, jobID: jobID, epoch: chunk.GetLeaseEpoch()}
		*subp = sub
	}
	if sub.id != submissionID {
		// One submission per stream. Interleaving two would make the resumption
		// point ambiguous, and last_chunk_accepted is what a scan point resumes
		// from.
		return malformed(submissionID, "a stream carries one submission"), nil
	}
	if chunk.GetIncomplete() {
		sub.incomplete = true
	}

	var ack *scanpointv1.SubmitAck

	err = s.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// ====================================================================
		// The epoch check. Every chunk, not just the first.
		// ====================================================================
		//
		// A superseded epoch yields ACCEPTED_QUARANTINED: stored, withheld from
		// the finding pipeline, surfaced to an operator. Never dropped and never
		// processed. The results are the record of what the job touched, which
		// is the content of ADR-012's operator escalation — the case where an
		// intrusive job died mid-flight and somebody has to know what it reached.
		//
		// Quarantine is sticky. A later chunk can quarantine a submission whose
		// earlier chunks passed, and every observation is promoted together at
		// the terminal ack — which is why they land pending rather than accepted.
		if !sub.quarantined {
			if reason := s.checkEpoch(ctx, c, spID, jobID, chunk.GetLeaseEpoch()); reason != "" {
				sub.quarantined = true
				sub.reason = reason
			}
		}

		// Create the ledger row on the first chunk. Idempotency lives here, at
		// the boundary: the finding dedup key is computed downstream of
		// correlation, by which point duplicates have already been merged into
		// assets (ADR-026).
		if sub.chunks == 0 {
			st := store.SubmitAccepted
			reason := ""
			if sub.quarantined {
				st, reason = store.SubmitAcceptedQuarantined, sub.reason
			}
			if _, err := (store.Submissions{}).Begin(ctx, c, submissionID, jobID,
				chunk.GetLeaseEpoch(), st, sub.incomplete, reason); err != nil {
				if errors.Is(err, store.ErrConflict) {
					// Return the sentinel rather than setting the ack and
					// returning nil. A unique violation ABORTS the transaction,
					// so committing after one fails — and the scan point would
					// be told RETRY_LATER, keep its buffer, and retry a
					// submission that is already ingested, forever.
					return errDuplicate
				}
				return err
			}
		}

		obs, err := s.toObservations(spID, submissionID, chunk)
		if err != nil {
			// Also a sentinel, and also to force a rollback: Begin may have
			// just created the ledger row, and a malformed chunk must not leave
			// a submission behind that nothing will ever complete.
			return fmt.Errorf("%w: %s", errMalformed, err.Error())
		}

		// Everything lands PENDING. The pipeline filters accepted, so an
		// in-flight submission is invisible to it without the pipeline knowing
		// submissions exist.
		if err := (store.Observations{}).InsertBatch(ctx, c, obs, store.IngestPending); err != nil {
			return err
		}
		if err := (store.Submissions{}).RecordChunk(ctx, c, submissionID,
			int(chunk.GetChunkIndex()), sub.incomplete); err != nil {
			return err
		}

		sub.chunks++
		sub.lastAccepted = chunk.GetChunkIndex()
		sub.hasAccepted = true

		if !chunk.GetFinal() {
			ack = &scanpointv1.SubmitAck{
				SubmissionId:      submissionID,
				LastChunkAccepted: chunk.GetChunkIndex(),
				Status:            scanpointv1.SubmitStatus_ACCEPTED,
			}
			return nil
		}

		// ====================================================================
		// Terminal: promote the whole submission, in this transaction.
		// ====================================================================
		//
		// The promotion and the last epoch check are atomic. A submission
		// promoted to accepted while its epoch was already superseded would put
		// results from a fenced-off scan point into the finding pipeline, and
		// that is the exact failure the pending state exists to prevent.
		to, st := store.IngestAccepted, store.SubmitAccepted
		wire := scanpointv1.SubmitStatus_ACCEPTED
		if sub.quarantined {
			to, st = store.IngestQuarantined, store.SubmitAcceptedQuarantined
			wire = scanpointv1.SubmitStatus_ACCEPTED_QUARANTINED
		}

		if _, err := (store.Observations{}).Promote(ctx, c, submissionID, to); err != nil {
			return err
		}
		if err := (store.Submissions{}).Complete(ctx, c, submissionID, st,
			terminationReason(chunk.GetTerminationReason()), sub.reason); err != nil {
			return err
		}

		if sub.quarantined {
			if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorID:      &spID,
				ActorType:    store.ActorScanPoint,
				Action:       "submission.quarantined",
				ResourceType: "scan_job",
				ResourceID:   &jobID,
				Detail: map[string]any{
					"submission_id": submissionID,
					"lease_epoch":   chunk.GetLeaseEpoch(),
					"reason":        sub.reason,
					"note":          "stored and withheld from the finding pipeline; never dropped (ADR-012, ADR-026)",
				},
			}); err != nil {
				return err
			}
		}

		ack = &scanpointv1.SubmitAck{
			SubmissionId:      submissionID,
			LastChunkAccepted: chunk.GetChunkIndex(),
			Status:            wire,
			Detail:            sub.reason,
		}
		return nil
	})

	// The two rejections travel as sentinels so their transactions roll back.
	// Both tell the scan point to CLEAR its buffer without retrying, which is
	// only safe because neither will succeed on a second attempt.
	if errors.Is(err, errDuplicate) {
		return &scanpointv1.SubmitAck{
			SubmissionId:      submissionID,
			LastChunkAccepted: chunk.GetChunkIndex(),
			Status:            scanpointv1.SubmitStatus_REJECTED_DUPLICATE,
			Detail:            "this submission_id has already been ingested",
		}, nil
	}
	if errors.Is(err, errMalformed) {
		return malformed(submissionID, strings.TrimPrefix(err.Error(), errMalformed.Error()+": ")), nil
	}

	if err != nil {
		// RETRY_LATER, not an error status. A transient Core-side failure must
		// tell the scan point to KEEP its buffer and back off; anything else
		// makes it clear results that were never stored (ADR-026).
		s.log.ErrorContext(ctx, "chunk ingest failed",
			slog.String("submission_id", submissionID), slog.Any("error", err))
		// The resumption point is the last chunk actually COMMITTED, not the one
		// that just failed — a scan point resuming from a chunk that rolled back
		// would leave a hole in the submission.
		ack := &scanpointv1.SubmitAck{
			SubmissionId: submissionID,
			Status:       scanpointv1.SubmitStatus_RETRY_LATER,
			RetryAfterMs: 2000,
			Detail:       "transient Core-side failure; keep the buffer and retry",
		}
		if sub.hasAccepted {
			ack.LastChunkAccepted = sub.lastAccepted
		}
		return ack, nil
	}
	return ack, nil
}

// checkEpoch returns a quarantine reason, or "" if the submission may proceed.
//
// Three ways to be quarantined, and all three are "stored, withheld, surfaced"
// rather than refused:
//
//	superseded    a higher epoch has been issued. The scan point lost its lease
//	              and kept going, or its submission was in flight when the job
//	              was reassigned.
//	from the future  an epoch Core never issued. Either our bug or an attempt;
//	              both need an operator, and neither is a reason to drop data.
//	wrong holder  the job is not this scan point's. Storing it under the real
//	              holder's job would corrupt that record, and dropping it would
//	              lose the evidence — the same handling ingest.proto prescribes
//	              for a zone the scan point was not enrolled into.
func (s *IngestService) checkEpoch(ctx context.Context, c *store.Conn, spID, jobID uuid.UUID, epoch int64) string {
	lease, err := (store.Leases{}).Current(ctx, c, jobID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "no lease has ever been issued for this job"
		}
		// A read failure is not a quarantine verdict. Returning "" here would
		// accept on a database error, which is the wrong direction; the caller's
		// transaction fails and the scan point is told RETRY_LATER.
		s.log.ErrorContext(ctx, "epoch check read failed", slog.Any("error", err))
		return ""
	}

	switch {
	case epoch < lease.Epoch:
		return fmt.Sprintf("superseded lease epoch: submitted %d, current %d", epoch, lease.Epoch)
	case epoch > lease.Epoch:
		return fmt.Sprintf("lease epoch %d was never issued (current %d)", epoch, lease.Epoch)
	case lease.HolderID != spID:
		return "the job's lease is held by a different scan point"
	}
	return ""
}

// toObservations converts a chunk, validating the open observation_type string
// against the closed ERD enum.
//
// The wire deliberately carries an open string, because engines are extensible
// and a closed enum would make every new observation type a protocol change.
// Core validating it here is the other half of that arrangement (ADR-006).
func (s *IngestService) toObservations(spID uuid.UUID, submissionID string, chunk *scanpointv1.ResultChunk) ([]store.Observation, error) {
	out := make([]store.Observation, 0, len(chunk.GetObservations()))
	for i, o := range chunk.GetObservations() {
		if !store.ValidObservationType(o.GetObservationType()) {
			return nil, fmt.Errorf("observation %d: unknown observation_type", i)
		}
		obsID, err := uuid.Parse(o.GetObservationId())
		if err != nil {
			return nil, fmt.Errorf("observation %d: malformed observation_id", i)
		}
		taskID, err := uuid.Parse(o.GetTaskId())
		if err != nil {
			return nil, fmt.Errorf("observation %d: malformed task_id", i)
		}
		zoneID, err := uuid.Parse(o.GetZoneId())
		if err != nil {
			return nil, fmt.Errorf("observation %d: malformed zone_id", i)
		}

		conf := float64(o.GetConfidence())
		observed := time.Unix(o.GetObservedAtUnix(), 0).UTC()
		if o.GetObservedAtUnix() == 0 {
			observed = s.now().UTC()
		}

		out = append(out, store.Observation{
			ID:           obsID,
			SubmissionID: submissionID,
			TaskID:       taskID,
			ScanPointID:  spID,
			ZoneID:       zoneID,
			Type:         store.ObservationType(o.GetObservationType()),
			Payload:      o.GetPayload(),
			Confidence:   &conf,
			ObservedAt:   observed,
		})
	}
	return out, nil
}

// malformed builds the ack that tells a scan point to clear its buffer without
// retrying. Unparseable input will not become parseable on a second attempt.
func malformed(submissionID, detail string) *scanpointv1.SubmitAck {
	return &scanpointv1.SubmitAck{
		SubmissionId: submissionID,
		Status:       scanpointv1.SubmitStatus_REJECTED_MALFORMED,
		Detail:       detail,
	}
}
