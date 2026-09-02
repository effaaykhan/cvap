package store

import (
	"context"
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
	TaskTarget string
	Status     string
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

	const q = `
		WITH claimed AS (
		    SELECT job_id
		      FROM scan_jobs
		     WHERE tenant_id = $1
		       AND status = 'queued'
		       AND engine = ANY($2::engine_kind[])
		     ORDER BY created_at
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

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), names, scanPointID, limit)
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

// Tasks returns a job's tasks, which is what the assignment carries.
func (Jobs) Tasks(ctx context.Context, c *Conn, jobID uuid.UUID) ([]Task, error) {
	const q = `
		SELECT task_id, job_id, target_id, task_target, status
		  FROM scan_tasks
		 WHERE tenant_id = $1 AND job_id = $2
		 ORDER BY task_id`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), jobID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.JobID, &t.TargetID, &t.TaskTarget, &t.Status); err != nil {
			return nil, mapError(err)
		}
		out = append(out, t)
	}
	return out, mapError(rows.Err())
}

// MarkRunning records that the scan point started work.
func (Jobs) MarkRunning(ctx context.Context, c *Conn, jobID uuid.UUID) error {
	const q = `
		UPDATE scan_jobs SET status = 'running'
		 WHERE tenant_id = $1 AND job_id = $2 AND status = 'assigned'`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID)
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
// The status is derived from the reason rather than taken from the scan point:
// a scan point reports what happened to it, and Core decides what that means for
// the job. `completed` for a clean finish; `failed` for everything else, which
// keeps "did this job produce trustworthy results" answerable without reading
// the reason.
func (Jobs) Terminate(ctx context.Context, c *Conn, jobID uuid.UUID, reason TerminationReason) error {
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
		   SET status = $3, termination_reason = $4, completed_at = now()
		 WHERE tenant_id = $1 AND job_id = $2
		   AND status IN ('assigned', 'running')`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, string(status), string(reason))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpiredLease is one job whose lease has run out, and what should happen to it.
type ExpiredLease struct {
	JobID        uuid.UUID
	ScanPointID  *uuid.UUID
	Epoch        int64
	ReassignSafe bool
	Requeued     bool
}
