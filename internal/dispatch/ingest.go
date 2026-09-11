package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
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
	errDuplicate      = errors.New("ingest: submission_id already ingested")
	errMalformed      = errors.New("ingest: malformed chunk")
	errConflictResume = errors.New("ingest: submission already exists; resume or reject")
)

// Bounds on wire values that reach typed columns.
//
// observed_at is the PARTITION KEY. An unbounded value from the wire chooses the
// partition, and a row in the default partition blocks creation of the real
// partition for that month — for the whole deployment, since partitions are not
// tenant-scoped. Migration 0009 names the failure: "a missing future partition
// is an ingest outage". One scan point in one tenant could cause it.
//
// Rows in the default partition also escape retention-by-partition-drop
// (ADR-016) and fall outside every bounded read window, so they are never
// correlated either.
const (
	maxObservationAge  = 90 * 24 * time.Hour // matches the retention window
	maxObservationSkew = time.Hour           // tolerate a scan point's clock drift
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

	// finished is set by the terminal chunk. See the check in handleChunk.
	finished bool

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

	var spID, enrolledZone uuid.UUID
	if err := s.db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByFingerprint(ctx, c, fingerprint)
		if err != nil {
			return err
		}
		spID = sp.ID
		// The zone this scan point was ENROLLED into. Observation.zone_id is
		// self-asserted and must be validated against it — see toObservations.
		enrolledZone = sp.ZoneID
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
			// Only when the terminal chunk never arrived. This warned on
			// every NORMAL completion too, because it checked that a
			// submission existed rather than that it had finished — and a
			// warning that fires on the happy path is one operators learn to
			// scroll past, which is worse than no warning at all.
			if sub != nil && !sub.finished {
				s.log.WarnContext(ctx, "submission stream ended without a final chunk",
					slog.String("submission_id", sub.id),
					slog.Int("chunks", sub.chunks))
			}
			return nil
		}
		if err != nil {
			return err
		}

		ack, err := s.handleChunk(ctx, tenant, spID, enrolledZone, &sub, chunk)
		if err != nil {
			return err
		}
		if err := stream.Send(ack); err != nil {
			return err
		}
	}
}

// handleChunk is one chunk, one transaction, one ack.
func (s *IngestService) handleChunk(ctx context.Context, tenant store.TenantID, spID, enrolledZone uuid.UUID, subp **submission, chunk *scanpointv1.ResultChunk) (*scanpointv1.SubmitAck, error) {
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
	if sub.finished {
		// `final` must mean final. Without this the receive loop accepts more
		// chunks after a terminal ack: the submission is completed twice, and
		// later chunks land pending and are promoted by the second Complete —
		// so one submission ends with some observations accepted and some
		// quarantined. An operator triaging the quarantine queue would see a
		// quarantined submission whose earlier half is already in the finding
		// pipeline, which is precisely the split the pending state exists to
		// prevent.
		return malformed(submissionID, "the submission already received a final chunk"), nil
	}
	if chunk.GetIncomplete() {
		sub.incomplete = true
	}

	// M4: every chunk must agree with the first about which job and which epoch
	// it belongs to. sub.jobID was captured on chunk 0 and never compared, so a
	// later chunk could name a different job — checkEpoch would evaluate that
	// one while the ledger row kept the first.
	if jobID != sub.jobID || chunk.GetLeaseEpoch() != sub.epoch {
		return malformed(submissionID,
			"job_id and lease_epoch must not change within a submission"), nil
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
			reason, err := s.checkEpoch(ctx, c, spID, jobID, chunk.GetLeaseEpoch())
			if err != nil {
				return err
			}
			if reason != "" {
				sub.quarantined = true
				sub.reason = reason
			}
		}

		// ====================================================================
		// The zone MUST, from ingest.proto and from the column comment on
		// scan_points.zone_id.
		// ====================================================================
		//
		// zone_id is self-asserted, and it is the field on this message where
		// that matters most: exposure is DERIVED from which vantage points saw
		// what (ADR-008), so a scan point free to name its own zone could
		// rewrite the derived exposure of every asset it reports — making an
		// internet-facing service look internal, or the reverse.
		//
		// Quarantined, not dropped and not silently re-zoned. Re-zoning would
		// hide the attempt; dropping would lose the record. The contract
		// prescribes exactly this handling, and it is the same reasoning
		// checkEpoch uses for its own reasons.
		// An UNSET zone_id is not a mismatch. It asserts nothing, so there is
		// nothing to disagree with, and Core substitutes the zone this scan
		// point was enrolled into.
		//
		// The field exists "because a scan point may straddle segments and
		// knows which interface saw the host, which Core cannot derive — not so
		// that it may choose" (ingest.proto). A runtime with one zone and one
		// vantage point has nothing to add, and EnrollResponse carries no zone
		// for it to echo — deliberately, since EnrollRequest carries none
		// either and a scan point must not influence its own vantage point
		// (ADR-008). Rejecting an empty value as malformed would leave the
		// contract with no way for a single-zone scan point to submit anything
		// at all.
		//
		// The security property is untouched: a scan point still cannot name a
		// zone it was not enrolled into, because a NON-empty value is compared
		// exactly as before and a mismatch still quarantines. What is given up
		// is catching a runtime bug that forgets to set the field — and in the
		// single-zone case the substituted answer is the correct one anyway.
		//
		// When a scan point genuinely straddles segments it will need to name
		// one of several, which needs its enrolled zones in EnrollResponse — an
		// additive field, and the point at which this substitution should
		// narrow to "unset means the sole enrolled zone".
		if !sub.quarantined {
			for _, o := range chunk.GetObservations() {
				if o.GetZoneId() == "" {
					continue
				}
				if o.GetZoneId() != enrolledZone.String() {
					sub.quarantined = true
					sub.reason = "observation names a zone this scan point was not enrolled into"
					break
				}
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
					// ============================================================
					// A conflict is not automatically a duplicate. It is usually
					// a RESUMPTION.
					// ============================================================
					//
					// The contract is explicitly resumable: SubmitAck carries
					// last_chunk_accepted so a scan point that loses its
					// connection reconnects and continues from there. That new
					// stream has fresh in-memory state, so chunks == 0 and this
					// runs — and answering REJECTED_DUPLICATE told the scan point
					// to clear a buffer for a submission that was never
					// completed. Its already-stored observations then sat pending
					// forever: not in the finding pipeline, not on the quarantine
					// queue, not reachable by anything. Results discarded, which
					// ADR-026 says never happens, and not surfaced either.
					//
					// So: rehydrate from the ledger row and continue. Only a
					// submission that actually COMPLETED is a duplicate.
					//
					// This also makes quarantine sticky ACROSS streams, which it
					// was not — it merely looked sticky because this path was
					// unreachable.
					return errConflictResume
				}
				return err
			}
		}

		// task_id is constrained by its FK to the TENANT, not to the job, so a
		// scan point could otherwise attribute observations to another scan
		// point's job — corrupting the "what did this job touch" record that
		// ADR-012's operator escalation depends on.
		if !sub.quarantined {
			ok, err := s.tasksBelongToJob(ctx, c, jobID, chunk)
			if err != nil {
				return err
			}
			if !ok {
				sub.quarantined = true
				sub.reason = "observation attributed to a task outside the submitted job"
			}
		}

		obs, err := s.toObservations(spID, enrolledZone, submissionID, chunk)
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
		// The tasks a terminal already judged, revisited now their results are
		// accepted (ADR-093 decision 3). Quarantined results are not coverage.
		if to == store.IngestAccepted {
			if err := (store.Jobs{}).ReconcileTasksWithResults(ctx, c, sub.jobID); err != nil {
				return err
			}
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

		sub.finished = true
		ack = &scanpointv1.SubmitAck{
			SubmissionId:      submissionID,
			LastChunkAccepted: chunk.GetChunkIndex(),
			Status:            wire,
			Detail:            sub.reason,
		}
		return nil
	})

	// A conflict means the ledger row exists. Whether that is a duplicate or a
	// resumption is a question about the EXISTING row, and it has to be asked in
	// a fresh transaction because the unique violation aborted this one.
	if errors.Is(err, errConflictResume) {
		return s.resume(ctx, tenant, spID, enrolledZone, sub, chunk)
	}

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

// resume continues a submission whose ledger row already exists.
//
// A completed submission is a genuine duplicate: the scan point lost the final
// ack and retried, and it should clear its buffer. An incomplete one is a
// resumption, and its state is rehydrated from the row so the stream continues
// where the previous one stopped.
func (s *IngestService) resume(ctx context.Context, tenant store.TenantID, spID, enrolledZone uuid.UUID, sub *submission, chunk *scanpointv1.ResultChunk) (*scanpointv1.SubmitAck, error) {
	var existing *store.Submission
	if err := s.db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		existing, err = (store.Submissions{}).Get(ctx, c, sub.id)
		return err
	}); err != nil {
		s.log.ErrorContext(ctx, "could not read the existing submission",
			slog.String("submission_id", sub.id), slog.Any("error", err))
		return &scanpointv1.SubmitAck{
			SubmissionId: sub.id,
			Status:       scanpointv1.SubmitStatus_RETRY_LATER,
			RetryAfterMs: 2000,
		}, nil
	}

	if existing.CompletedAt != nil {
		return &scanpointv1.SubmitAck{
			SubmissionId:      sub.id,
			LastChunkAccepted: chunk.GetChunkIndex(),
			Status:            scanpointv1.SubmitStatus_REJECTED_DUPLICATE,
			Detail:            "this submission has already been completed",
		}, nil
	}

	// Rehydrate. Quarantine carries across streams: a submission quarantined on
	// a previous connection stays quarantined, whatever this chunk's epoch says.
	sub.chunks = existing.ChunksReceived
	sub.incomplete = existing.Incomplete
	if existing.Status == store.SubmitAcceptedQuarantined {
		sub.quarantined = true
		if existing.QuarantineReason != nil {
			sub.reason = *existing.QuarantineReason
		}
	}
	if existing.LastChunkAccepted != nil {
		// The ledger column is a plain integer, so the conversion back to the
		// wire's uint32 has to be checked rather than asserted. A wrapped value
		// here is not cosmetic: lastAccepted is what tells a resuming scan point
		// which chunks it need not re-send, so a negative row read as a huge
		// uint32 would acknowledge chunks that were never stored and the
		// observations in them would be lost silently.
		v := *existing.LastChunkAccepted
		if v < 0 || v > math.MaxUint32 {
			return nil, fmt.Errorf("submission ledger holds last_chunk_accepted=%d, "+
				"which is not a chunk index", v)
		}
		sub.lastAccepted = uint32(v)
		sub.hasAccepted = true

		// Already ingested. Acknowledge rather than re-store: re-inserting would
		// hit the observation primary key and abort, and the scan point is
		// resuming from what we told it.
		if chunk.GetChunkIndex() <= sub.lastAccepted {
			return &scanpointv1.SubmitAck{
				SubmissionId:      sub.id,
				LastChunkAccepted: sub.lastAccepted,
				Status:            scanpointv1.SubmitStatus_ACCEPTED,
				Detail:            "already ingested; resume from the next chunk",
			}, nil
		}
	}

	// chunks is now non-zero, so the retry does not re-enter Begin.
	return s.handleChunk(ctx, tenant, spID, enrolledZone, &sub, chunk)
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
func (s *IngestService) checkEpoch(ctx context.Context, c *store.Conn, spID, jobID uuid.UUID, epoch int64) (string, error) {
	lease, err := (store.Leases{}).Current(ctx, c, jobID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "no lease has ever been issued for this job", nil
		}
		// A read failure is not a quarantine verdict, and it is not an
		// acceptance either.
		//
		// This returned a bare string. The comment claimed a read failure meant
		// "the caller's transaction fails and the scan point is told
		// RETRY_LATER" — but the caller only ever tested `reason != ""`, so a
		// database error read as "epoch fine, carry on" and the submission was
		// accepted with its fencing check silently skipped. That is the exact
		// shape of failure ADR-012 exists to prevent, reachable by anything that
		// makes one read fail while the transaction can still commit.
		//
		// The error is returned so it cannot be mistaken for a verdict. The
		// caller rolls back and answers RETRY_LATER, which is the conservative
		// direction: a scan point retries, and ADR-026 keeps the results.
		s.log.ErrorContext(ctx, "epoch check read failed", slog.Any("error", err))
		return "", fmt.Errorf("epoch check: %w", err)
	}

	switch {
	case epoch < lease.Epoch:
		return fmt.Sprintf("superseded lease epoch: submitted %d, current %d", epoch, lease.Epoch), nil
	case epoch > lease.Epoch:
		return fmt.Sprintf("lease epoch %d was never issued (current %d)", epoch, lease.Epoch), nil
	case lease.HolderID != spID:
		return "the job's lease is held by a different scan point", nil
	}
	return "", nil
}

// tasksBelongToJob checks every task_id in the chunk against the job.
func (s *IngestService) tasksBelongToJob(ctx context.Context, c *store.Conn, jobID uuid.UUID, chunk *scanpointv1.ResultChunk) (bool, error) {
	seen := map[string]bool{}
	for _, o := range chunk.GetObservations() {
		seen[o.GetTaskId()] = true
	}
	if len(seen) == 0 {
		return true, nil
	}

	tasks, err := (store.Jobs{}).Tasks(ctx, c, jobID)
	if err != nil {
		return false, err
	}
	valid := make(map[string]bool, len(tasks))
	for _, t := range tasks {
		valid[t.ID.String()] = true
	}
	for id := range seen {
		if !valid[id] {
			return false, nil
		}
	}
	return true, nil
}

// toObservations converts a chunk, validating the open observation_type string
// against the closed ERD enum.
//
// The wire deliberately carries an open string, because engines are extensible
// and a closed enum would make every new observation type a protocol change.
// Core validating it here is the other half of that arrangement (ADR-006).
func (s *IngestService) toObservations(spID, enrolledZone uuid.UUID, submissionID string, chunk *scanpointv1.ResultChunk) ([]store.Observation, error) {
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
		// Unset means "the zone this scan point was enrolled into" — see the
		// substitution in handleChunk. A non-empty value that will not parse is
		// still malformed.
		zoneID := enrolledZone
		if raw := o.GetZoneId(); raw != "" {
			zoneID, err = uuid.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("observation %d: malformed zone_id", i)
			}
		}

		// Every one of these has a typed column behind it with a constraint. A
		// value that fails there kills the whole transaction and the scan point
		// is told RETRY_LATER — "keep your buffer and retry" for input that can
		// never succeed, forever. REJECTED_MALFORMED is the correct answer and
		// the path already exists; it just was not reached.
		conf := float64(o.GetConfidence())
		if math.IsNaN(conf) || math.IsInf(conf, 0) || conf < 0 || conf > 1 {
			return nil, fmt.Errorf("observation %d: confidence out of range", i)
		}

		if len(o.GetPayload()) == 0 || !json.Valid(o.GetPayload()) {
			// payload is jsonb NOT NULL, and an unset bytes field is "" — which
			// is not valid JSON.
			return nil, fmt.Errorf("observation %d: payload is not valid JSON", i)
		}

		observed := s.now().UTC()
		if ts := o.GetObservedAtUnix(); ts != 0 {
			observed = time.Unix(ts, 0).UTC()
			now := s.now().UTC()
			if observed.Before(now.Add(-maxObservationAge)) || observed.After(now.Add(maxObservationSkew)) {
				return nil, fmt.Errorf("observation %d: observed_at outside the retention window", i)
			}
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
