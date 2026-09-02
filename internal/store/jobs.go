package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// JobStatus mirrors the job_status enum.
type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobAssigned  JobStatus = "assigned"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"

	// JobQuarantined: results held from the finding pipeline (ADR-012,
	// ADR-026). The job ran; what it produced is withheld.
	JobQuarantined JobStatus = "quarantined"

	JobCancelled JobStatus = "cancelled"
	JobKilled    JobStatus = "killed"
)

// Job is one unit assigned to one scan point, one engine, roughly minutes of
// work (ADR-011). The unit of leasing, retry and progress.
type Job struct {
	ID          uuid.UUID
	ScanID      uuid.UUID
	ScanPointID *uuid.UUID
	Engine      Engine
	Status      JobStatus
	Attempt     int

	// ReassignSafe governs RETRY, not retention (ADR-012). Results from a job
	// that lost its lease are persisted unconditionally (ADR-026); this decides
	// only whether the work re-runs. Orthogonal to safety_mode (ADR-021).
	ReassignSafe bool

	TerminationReason *TerminationReason
	CreatedAt         time.Time
	CompletedAt       *time.Time
}

// Task is individual target work inside a job, and the unit of observation
// attribution (ADR-011).
type Task struct {
	ID         uuid.UUID
	JobID      uuid.UUID
	TargetID   *uuid.UUID
	AssetID    *uuid.UUID
	TaskTarget string
	Status     string

	// Fragile caps rate regardless of policy (ADR-024 control 3), and travels
	// per task because fragility belongs to the DEVICE rather than to the scan:
	// it must apply to every scan that ever touches it, including one written by
	// someone who has never heard of that device.
	//
	// Derived from assets.fragile through scan_tasks.asset_id. A task with no
	// asset is not fragile — the permissive direction, chosen because treating
	// unknown as fragile would throttle every discovery scan to 10 pps, and a
	// device known to be fragile is one Core has already seen.
	Fragile bool
}

type Jobs struct{}

// Claim takes up to limit queued jobs for one scan point, for engines it can
// run, and marks them assigned.
//
// ============================================================================
// FOR UPDATE SKIP LOCKED, and what it does and does not give you.
// ============================================================================
//
// ADR-003 puts dispatch in Postgres rather than a broker, and SKIP LOCKED is the
// mechanism. Two dispatchers running this concurrently do not contend: the
// second does not wait on a locked row and then lose, it does not SEE that row
// at all. So no job is ever handed to two scan points by a race here.
//
// The predicate does the rest. After the first transaction commits the row is
// `assigned`, so `WHERE status = 'queued'` excludes it from every later claim —
// which is what makes the guarantee survive the lock being released.
//
// Neither of those is where at-most-once is actually won or lost. That is
// ExpireLeases: a job whose lease expired goes back to the queue only if it is
// reassign_safe, and a non-reassign_safe job fails loudly instead. Duplicating
// active or intrusive work harms the target, so ADR-012 makes that an operator
// escalation rather than a retry.
//
// The engines filter is the capability ceiling from the other side: Core never
// dispatches an engine a scan point has not declared, and the declaration can
// only ever WITHHOLD work. It is not consulted for authorisation.
func (Jobs) Claim(ctx context.Context, c *Conn, scanPointID uuid.UUID, engines []Engine, limit int) ([]Job, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	if len(engines) == 0 {
		return nil, nil
	}

	names := make([]string, len(engines))
	for i, e := range engines {
		names[i] = string(e)
	}

	// Two predicates beyond "queued and an engine you can run", and both are
	// safety controls rather than optimisations.
	//
	// authorization_verified: migration 0005 says outright that dispatch must
	// refuse to decompose a target where this is false, and execution-plan §8
	// risk 6 calls an unauthorised scan legal exposure, potentially criminal.
	// Dispatch is the last Core-side component before a target leaves Core, so
	// if the check is not here it is nowhere. A task with a NULL target_id has
	// no authorisation record at all and is refused for the same reason.
	//
	// A live kill switch stops assignment. Without this, propagateKills halts
	// the fleet's in-flight work and offerWork hands out fresh jobs two seconds
	// later, forever — which is not a kill switch.
	const q = `
		WITH claimed AS (
		    SELECT j.job_id
		      FROM scan_jobs j
		     WHERE j.tenant_id = $1
		       AND j.status = 'queued'
		       AND j.engine = ANY($2::engine_kind[])
		       AND j.attempt < $5
		       AND NOT EXISTS (
		           SELECT 1 FROM kill_switches k
		            WHERE k.tenant_id = j.tenant_id
		              AND k.resolved_at IS NULL
		              AND (k.scope = 'tenant'
		                   OR (k.scope = 'scan' AND k.scope_scan_id = j.scan_id))
		       )
		       AND EXISTS (
		           SELECT 1 FROM scan_tasks t
		            WHERE t.tenant_id = j.tenant_id AND t.job_id = j.job_id
		       )
		       AND NOT EXISTS (
		           SELECT 1 FROM scan_tasks t
		            LEFT JOIN scan_targets tg
		                   ON tg.tenant_id = t.tenant_id AND tg.target_id = t.target_id
		            WHERE t.tenant_id = j.tenant_id AND t.job_id = j.job_id
		              AND (t.target_id IS NULL OR tg.authorization_verified IS NOT TRUE)
		       )
		     ORDER BY j.created_at
		     LIMIT $4
		     FOR UPDATE SKIP LOCKED
		)
		UPDATE scan_jobs j
		   SET status        = 'assigned',
		       scan_point_id = $3,
		       attempt       = j.attempt + 1
		  FROM claimed
		 WHERE j.tenant_id = $1 AND j.job_id = claimed.job_id
		RETURNING j.job_id, j.scan_id, j.scan_point_id, j.engine, j.status,
		          j.attempt, j.reassign_safe, j.termination_reason,
		          j.created_at, j.completed_at`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), names, scanPointID, limit, MaxAttempts)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.ScanID, &j.ScanPointID, &j.Engine, &j.Status,
			&j.Attempt, &j.ReassignSafe, &j.TerminationReason,
			&j.CreatedAt, &j.CompletedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, j)
	}
	return out, mapError(rows.Err())
}

func (Jobs) GetByID(ctx context.Context, c *Conn, id uuid.UUID) (*Job, error) {
	const q = `
		SELECT job_id, scan_id, scan_point_id, engine, status, attempt,
		       reassign_safe, termination_reason, created_at, completed_at
		  FROM scan_jobs
		 WHERE tenant_id = $1 AND job_id = $2`

	var j Job
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).
		Scan(&j.ID, &j.ScanID, &j.ScanPointID, &j.Engine, &j.Status, &j.Attempt,
			&j.ReassignSafe, &j.TerminationReason, &j.CreatedAt, &j.CompletedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &j, nil
}

// MaxTasksPerAssignment bounds what one JobAssignment can carry.
//
// The whole task set goes into one message and the wire cap is 4MB
// (execution-plan §5), so an unbounded read here produces a Send that fails
// AFTER the job is marked assigned and leased: undeliverable, and stuck until
// the sweeper expires it.
const MaxTasksPerAssignment = 1000

// ErrTooManyTasks means a job cannot be expressed as one assignment.
//
// Returned rather than silently truncating, and the difference matters more than
// it looks. A LIMIT that quietly returned the first 1000 tasks would hand the
// scan point a job it could complete successfully while never touching the
// remaining targets — the scan reports done, coverage is short, and nothing
// anywhere says so. Under-scanning that looks like a clean run is the worst
// failure this system has, because the customer acts on it.
//
// Failing here rolls back the caller's transaction, which un-claims the job: it
// returns to 'queued' and dispatch logs the error on every poll. Noisy on
// purpose. The fix is to decompose the job at planning time (ADR-011 sizes a job
// at roughly minutes of work), not to raise this constant.
var ErrTooManyTasks = errors.New("store: job has more tasks than one assignment can carry")

// Tasks returns a job's tasks, which is what the assignment carries.
func (Jobs) Tasks(ctx context.Context, c *Conn, jobID uuid.UUID) ([]Task, error) {
	const q = `
		SELECT t.task_id, t.job_id, t.target_id, t.asset_id, t.task_target, t.status,
		       coalesce(a.fragile, false)
		  FROM scan_tasks t
		  LEFT JOIN assets a
		         ON a.tenant_id = t.tenant_id AND a.asset_id = t.asset_id
		 WHERE t.tenant_id = $1 AND t.job_id = $2
		 ORDER BY t.task_id
		 LIMIT $3`

	// One more than the cap, so a job that is over it is DETECTED rather than
	// trimmed to fit.
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), jobID, MaxTasksPerAssignment+1)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.JobID, &t.TargetID, &t.AssetID,
			&t.TaskTarget, &t.Status, &t.Fragile); err != nil {
			return nil, mapError(err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	if len(out) > MaxTasksPerAssignment {
		return nil, fmt.Errorf("%w: job %s has more than %d tasks",
			ErrTooManyTasks, jobID, MaxTasksPerAssignment)
	}
	return out, nil
}

// MarkRunning records that the scan point started work.
//
// scanPointID is in the predicate. See Terminate for why.
func (Jobs) MarkRunning(ctx context.Context, c *Conn, jobID, scanPointID uuid.UUID) error {
	const q = `
		UPDATE scan_jobs SET status = 'running'
		 WHERE tenant_id = $1 AND job_id = $2 AND scan_point_id = $3 AND status = 'assigned'`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, scanPointID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Terminate records how a job ended.
//
// ============================================================================
// scanPointID is in the predicate, and its absence was an IDOR.
// ============================================================================
//
// job_id arrives on JobTerminal from the scan point. Without a holder clause the
// predicate is "this tenant, this job, currently running" — which any scan point
// in the tenant satisfies for any other scan point's job. A security review
// proved it: scan point B terminated a job leased to A, A's next renewal then
// found nothing and A self-aborted and zeroised per ADR-012, and because the job
// was terminal no sweep would ever recover it. One compromised scan point
// silently kills every other scan point's in-flight work in the tenant.
//
// Leases.Renew was the counter-example done right all along: it takes the holder
// from the resolved session and puts it in the predicate. This does the same.
// Identity being correctly resolved is not the same as the OBJECT being
// authorised, and that gap is what the review found.
//
// The status is derived from the reason rather than taken from the scan point: a
// scan point reports what happened to it, and Core decides what that means for
// the job.
func (Jobs) Terminate(ctx context.Context, c *Conn, jobID, scanPointID uuid.UUID, reason TerminationReason) error {
	status := JobFailed
	switch reason {
	case TerminationCompleted:
		status = JobCompleted
	case TerminationCancelled:
		status = JobCancelled
	case TerminationKilled:
		status = JobKilled
	}

	const q = `
		UPDATE scan_jobs
		   SET status = $4, termination_reason = $5, completed_at = now()
		 WHERE tenant_id = $1 AND job_id = $2 AND scan_point_id = $3
		   AND status IN ('assigned', 'running')`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, scanPointID, string(status), string(reason))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MaxAttempts bounds how often one job may be re-queued.
//
// attempt was incremented and never read, so a reassign_safe job that kept
// losing its lease could be re-claimed forever — unbounded repeated scanning of
// a customer's target, driven by a Core-side loop rather than by anything an
// operator asked for. ADR-024 is about blast radius, and an infinite retry is
// blast radius spread over time.
const MaxAttempts = 5

// ExpiredLease is one job whose lease has run out, and what should happen to it.
type ExpiredLease struct {
	JobID        uuid.UUID
	ScanPointID  *uuid.UUID
	Epoch        int64
	ReassignSafe bool
	Requeued     bool
}
