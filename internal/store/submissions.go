package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// SubmitStatus mirrors the submit_status enum and SubmitStatus in ingest.proto.
//
// Five outcomes because two are not enough to tell a scan point what to do with
// its buffer (ADR-026).
type SubmitStatus string

const (
	// SubmitAccepted: processed normally.
	SubmitAccepted SubmitStatus = "accepted"

	// SubmitAcceptedQuarantined: stored, withheld from the finding pipeline,
	// operator-surfaced. NEVER dropped. This is what a superseded lease epoch
	// yields (ADR-012): the results are the record of what the job touched,
	// which is the content of the operator escalation.
	SubmitAcceptedQuarantined SubmitStatus = "accepted_quarantined"

	SubmitRejectedDuplicate SubmitStatus = "rejected_duplicate"
	SubmitRejectedMalformed SubmitStatus = "rejected_malformed"
	SubmitRetryLater        SubmitStatus = "retry_later"
)

// TerminationReason mirrors the termination_reason enum and common.proto.
type TerminationReason string

const (
	TerminationCompleted          TerminationReason = "completed"
	TerminationLeaseLost          TerminationReason = "lease_lost"
	TerminationCancelled          TerminationReason = "cancelled"
	TerminationKilled             TerminationReason = "killed"
	TerminationEngineFailure      TerminationReason = "engine_failure"
	TerminationWindowExpired      TerminationReason = "window_expired"
	TerminationScopeViolationHalt TerminationReason = "scope_violation_halt"
)

// Submission is the idempotency ledger row (ADR-026, ADR-029).
type Submission struct {
	ID                string
	JobID             uuid.UUID
	LeaseEpoch        int64
	Status            SubmitStatus
	ChunksReceived    int
	LastChunkAccepted *int
	Incomplete        bool
	TerminationReason *TerminationReason
	QuarantineReason  *string
	ReceivedAt        time.Time
	CompletedAt       *time.Time
}

type Submissions struct{}

// ErrQuarantineReasonRequired is returned before the database would reject the
// row, so the caller gets a message about the invariant rather than a CHECK
// constraint name.
var ErrQuarantineReasonRequired = errors.New(
	"store: a quarantined submission needs a quarantine reason; an escalation an operator cannot action is not an escalation")

// Begin records a new submission, or reports that this submission_id has
// already been ingested.
//
// Idempotency lives here, at the boundary, and not downstream: the finding
// dedup key (ADR-010) is computed after correlation, by which point duplicate
// observations have already been merged into assets. A scan point that submits
// and loses the connection before the ack WILL retry, so this path is on the
// normal course of events rather than an error case.
//
// Returns ErrConflict when the submission_id is already known — which the
// caller should turn into REJECTED_DUPLICATE, telling the scan point to clear
// its buffer without retrying.
func (Submissions) Begin(ctx context.Context, c *Conn, submissionID string, jobID uuid.UUID, leaseEpoch int64, status SubmitStatus, incomplete bool, quarantineReason string) (*Submission, error) {
	if status == SubmitAcceptedQuarantined && quarantineReason == "" {
		return nil, ErrQuarantineReasonRequired
	}

	const q = `
		INSERT INTO result_submissions
		    (submission_id, tenant_id, job_id, lease_epoch, status, incomplete, quarantine_reason)
		VALUES ($1, $2, $3, $4, $5, $6, nullif($7, ''))
		RETURNING submission_id, job_id, lease_epoch, status, chunks_received,
		          last_chunk_accepted, incomplete, termination_reason,
		          quarantine_reason, received_at, completed_at`

	var s Submission
	err := c.QueryRow(ctx, q, submissionID, c.Tenant().UUID(), jobID, leaseEpoch,
		string(status), incomplete, quarantineReason).
		Scan(&s.ID, &s.JobID, &s.LeaseEpoch, &s.Status, &s.ChunksReceived,
			&s.LastChunkAccepted, &s.Incomplete, &s.TerminationReason,
			&s.QuarantineReason, &s.ReceivedAt, &s.CompletedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &s, nil
}

// RecordChunk advances the resumption point.
//
// incomplete is written on EVERY chunk rather than only the final one: with
// resumption Core may process chunks before it ever sees final, and a flag that
// arrives last cannot stop the finding pipeline from having already run. Once
// true it stays true — hence the OR.
func (Submissions) RecordChunk(ctx context.Context, c *Conn, submissionID string, chunkIndex int, incomplete bool) error {
	const q = `
		UPDATE result_submissions
		   SET chunks_received     = chunks_received + 1,
		       last_chunk_accepted = greatest(coalesce(last_chunk_accepted, -1), $3),
		       incomplete          = incomplete OR $4
		 WHERE tenant_id = $1 AND submission_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), submissionID, chunkIndex, incomplete)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Complete closes a submission out with its terminal status and reason.
func (Submissions) Complete(ctx context.Context, c *Conn, submissionID string, status SubmitStatus, reason TerminationReason, quarantineReason string) error {
	if status == SubmitAcceptedQuarantined && quarantineReason == "" {
		return ErrQuarantineReasonRequired
	}

	const q = `
		UPDATE result_submissions
		   SET status             = $3,
		       termination_reason = $4,
		       quarantine_reason  = coalesce(nullif($5, ''), quarantine_reason),
		       completed_at       = now()
		 WHERE tenant_id = $1 AND submission_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), submissionID, string(status), string(reason), quarantineReason)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (Submissions) Get(ctx context.Context, c *Conn, submissionID string) (*Submission, error) {
	const q = `
		SELECT submission_id, job_id, lease_epoch, status, chunks_received,
		       last_chunk_accepted, incomplete, termination_reason,
		       quarantine_reason, received_at, completed_at
		  FROM result_submissions
		 WHERE tenant_id = $1 AND submission_id = $2`

	var s Submission
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), submissionID).
		Scan(&s.ID, &s.JobID, &s.LeaseEpoch, &s.Status, &s.ChunksReceived,
			&s.LastChunkAccepted, &s.Incomplete, &s.TerminationReason,
			&s.QuarantineReason, &s.ReceivedAt, &s.CompletedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &s, nil
}

// ListQuarantined is the operator queue: submissions stored but withheld from
// the finding pipeline. Nothing is dropped, so this queue is the only place
// some of that data is ever seen.
func (Submissions) ListQuarantined(ctx context.Context, c *Conn, limit int) ([]Submission, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	const q = `
		SELECT submission_id, job_id, lease_epoch, status, chunks_received,
		       last_chunk_accepted, incomplete, termination_reason,
		       quarantine_reason, received_at, completed_at
		  FROM result_submissions
		 WHERE tenant_id = $1 AND status = 'accepted_quarantined'
		 ORDER BY received_at DESC
		 LIMIT $2`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Submission
	for rows.Next() {
		var s Submission
		if err := rows.Scan(&s.ID, &s.JobID, &s.LeaseEpoch, &s.Status, &s.ChunksReceived,
			&s.LastChunkAccepted, &s.Incomplete, &s.TerminationReason,
			&s.QuarantineReason, &s.ReceivedAt, &s.CompletedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, s)
	}
	return out, mapError(rows.Err())
}
