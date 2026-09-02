package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// ADR-024 control 4, measured. The argument for KillAck applies unchanged.
// ============================================================================
//
// ADR-024 requires KillAck because "a 10-second bound Core cannot measure is not
// a control". Narrowing the blast radius does not weaken that: an operator who
// cancels one runaway scan and cannot tell whether it stopped has a button, not
// a control. Until this existed, "cancellation sent" was the last thing Core
// knew, and a scan point that dropped the message was indistinguishable from one
// that halted.
//
// The shape mirrors kill_acks in migration 0019 on purpose. The incident
// question is the same one — which scan points have NOT acknowledged — and it
// has to be a query rather than a scan over a text-keyed log.

// CancelAck is one scan point's acknowledgement of one cancelled job.
type CancelAck struct {
	JobID       uuid.UUID
	ScanPointID uuid.UUID

	// Epoch is the incarnation the scan point halted, echoed from CancelJob.
	// A cancellation acknowledged under a stale epoch stopped work Core was no
	// longer asking about (ADR-012).
	Epoch int64

	AckedAt     time.Time
	TasksHalted int

	// Latency is nil when it cannot be computed, NOT zero.
	//
	// The measurement runs from scans.cancel_requested_at. KillSwitches.Issue
	// sets it for a scan-scoped kill, and whatever cancels a scan must set it in
	// the same statement (migration 0025). Reporting an unmeasured bound as "0s"
	// would be a gate that silently passes, which this repository treats as
	// worse than one that fails.
	Latency *time.Duration
}

// UnackedCancellation is one job that was told to stop and has not said it did.
type UnackedCancellation struct {
	JobID       uuid.UUID
	ScanPointID uuid.UUID
	Status      JobStatus
}

type CancelAcks struct{}

// Record stores one acknowledgement, if one was actually owed.
//
// ============================================================================
// An acknowledgement Core did not ask for is not an acknowledgement.
// ============================================================================
//
// The first version validated `epoch > 0` and nothing else, which made the whole
// measurement forgeable in the one direction that matters. A scan point holding
// a job could send CancelAck at connect time, before any operator action; hours
// later an operator cancels the runaway scan, Core keeps sending CancelJob, the
// scan point keeps scanning — and Unacknowledged, the incident view this table
// exists to provide, reports nothing outstanding. Pre-acknowledging your own
// future cancellation is not a control, it is a way to disappear from one.
//
// So the INSERT is conditional on the rows that prove the request was owed: this
// scan point holds an unreleased lease on that job at that epoch, and the scan is
// actually stopped. It is the shape Leases.Renew uses — the refusal IS the
// control — and the same predicate CancellableFor uses to decide what to send,
// so Core cannot ask for an acknowledgement it will then refuse to accept.
//
// The epoch is compared rather than merely stored. Three comments (this file,
// migration 0025, and CancelAck on the wire) promised a stale epoch would be
// visible rather than counted, and nothing read the column. Now a mismatch
// matches no row and the job stays in the chase set, which is the conservative
// reading: Core did not get an answer about the incarnation it asked about.
//
// Idempotent: a scan point that reconnects and acks again must not produce a
// second row, or "how many acknowledged" stops meaning anything. Same reasoning
// as KillSwitches.Ack.
//
// scanPointID comes from the resolved session, never from the message. Every
// value on that stream originates in a network whose compromise the threat model
// assumes (ADR-020), and an ack attributed to whoever the sender named would let
// one scan point mark another's cancellation acknowledged — the same class of
// defect as the missing holder predicate a security review found on
// Jobs.Terminate.
//
// Returns ErrNotFound when nothing was owed. The caller logs it; it is not a
// Core fault, and the job simply stays unacknowledged. A REPEAT of an
// acknowledgement already held returns nil, not ErrNotFound — a scan point that
// reconnects and acks again has done nothing wrong, and collapsing the two
// would make the honest retry indistinguishable from the forged ack.
func (CancelAcks) Record(ctx context.Context, c *Conn, jobID, scanPointID uuid.UUID, epoch int64, tasksHalted int) error {
	if epoch <= 0 {
		// The column has a CHECK, and this is the half that does not make the
		// database produce the error message. An epoch of zero names no
		// incarnation, so there is nothing to record it against (ADR-012).
		return fmt.Errorf("store: cancel ack for job %s carries no lease epoch", jobID)
	}
	if tasksHalted < 0 {
		tasksHalted = 0
	}

	const q = `
		INSERT INTO cancel_acks (tenant_id, job_id, scan_point_id, lease_epoch, tasks_halted)
		SELECT $1, j.job_id, $3, $4, $5
		  FROM scan_jobs j
		  JOIN scans s ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		 WHERE j.tenant_id = $1
		   AND j.job_id = $2
		   AND s.status IN ('cancelled', 'killed')
		   AND EXISTS (
		       SELECT 1 FROM job_leases l
		        WHERE l.tenant_id = j.tenant_id AND l.job_id = j.job_id
		          AND l.holder_scan_point = $3
		          AND l.epoch = $4
		          AND l.state <> 'released'
		   )
		ON CONFLICT (tenant_id, job_id, scan_point_id) DO NOTHING`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, scanPointID, epoch, tasksHalted)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() > 0 {
		return nil
	}

	// Zero rows means one of two different things, and only one of them is
	// interesting. ON CONFLICT DO NOTHING swallows the honest retry, and the
	// conditional SELECT swallows the ack that was never owed. One cheap lookup
	// separates them, so the caller's log says which happened.
	const already = `
		SELECT 1 FROM cancel_acks
		 WHERE tenant_id = $1 AND job_id = $2 AND scan_point_id = $3`

	var one int
	switch err := c.QueryRow(ctx, already, c.Tenant().UUID(), jobID, scanPointID).Scan(&one); {
	case err == nil:
		return nil
	case errors.Is(mapError(err), ErrNotFound):
		return ErrNotFound
	default:
		return mapError(err)
	}
}

// ForScan returns the acknowledgements for one cancelled scan, slowest first.
//
// This is the HOW LONG. Unacknowledged is the WHO, and ADR-024's bound needs
// both — a set of missing scan points says who is absent, not whether the ones
// who answered were fast enough.
func (CancelAcks) ForScan(ctx context.Context, c *Conn, scanID uuid.UUID) ([]CancelAck, error) {
	const q = `
		SELECT a.job_id, a.scan_point_id, a.lease_epoch, a.acked_at, a.tasks_halted,
		       CASE WHEN s.cancel_requested_at IS NULL THEN NULL
		            ELSE extract(epoch FROM (a.acked_at - s.cancel_requested_at)) * 1000
		       END
		  FROM cancel_acks a
		  JOIN scan_jobs j ON j.tenant_id = a.tenant_id AND j.job_id = a.job_id
		  JOIN scans s     ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		 WHERE a.tenant_id = $1 AND j.scan_id = $2
		 ORDER BY 6 DESC NULLS LAST, a.job_id`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []CancelAck
	for rows.Next() {
		var a CancelAck
		var ms *float64
		if err := rows.Scan(&a.JobID, &a.ScanPointID, &a.Epoch, &a.AckedAt, &a.TasksHalted, &ms); err != nil {
			return nil, mapError(err)
		}
		if ms != nil {
			d := time.Duration(*ms) * time.Millisecond
			a.Latency = &d
		}
		out = append(out, a)
	}
	return out, mapError(rows.Err())
}

// Unacknowledged is the set an operator chases: jobs under a cancelled or killed
// scan that a scan point is still holding and has not acknowledged stopping.
//
// Only 'assigned' and 'running' jobs appear, which is the same filter
// Jobs.CancellableFor uses to decide what to send. A job that has since reached
// a terminal state stopped, whatever it did or did not say about it, and leaving
// it here would mean the set never empties and stops being actionable — the
// reason KillSwitches.Unacknowledged excludes scan points that were never
// reachable.
func (CancelAcks) Unacknowledged(ctx context.Context, c *Conn, scanID uuid.UUID) ([]UnackedCancellation, error) {
	const q = `
		SELECT j.job_id, j.scan_point_id, j.status
		  FROM scan_jobs j
		  JOIN scans s ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		 WHERE j.tenant_id = $1
		   AND j.scan_id = $2
		   AND j.scan_point_id IS NOT NULL
		   AND j.status IN ('assigned', 'running')
		   AND s.status IN ('cancelled', 'killed')
		   AND NOT EXISTS (
		       SELECT 1 FROM cancel_acks a
		        WHERE a.tenant_id = j.tenant_id
		          AND a.job_id = j.job_id
		          AND a.scan_point_id = j.scan_point_id
		   )
		 ORDER BY j.created_at`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []UnackedCancellation
	for rows.Next() {
		var u UnackedCancellation
		if err := rows.Scan(&u.JobID, &u.ScanPointID, &u.Status); err != nil {
			return nil, mapError(err)
		}
		out = append(out, u)
	}
	return out, mapError(rows.Err())
}
