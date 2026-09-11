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
//
// windowClosedPolicies is how scan_policies.time_windows reaches this decision.
// The recurring schedule is evaluated in Go — see internal/dispatch/windows.go —
// and the policies that are outside their window right now arrive here as ids to
// exclude. It is a predicate rather than a post-claim check on purpose: a job
// claimed and then put back would burn an attempt on every poll and hit
// MaxAttempts inside ten seconds, so a maintenance window would destroy the scan
// it was written to protect. A closed window must leave the job QUEUED, not fail
// it. An empty or nil slice means no policy is closed, which is also what a
// tenant with no windowed policies at all looks like (ADR-037: empty means
// unrestricted for a list that enumerates constraint).
func (Jobs) Claim(ctx context.Context, c *Conn, scanPointID uuid.UUID, engines []Engine, limit int, windowClosedPolicies []uuid.UUID) ([]Job, error) {
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

	// Sent as text and cast, so the encoding of a uuid array is not left to
	// depend on which type map the pool happens to carry. Never nil: a NULL
	// array makes `= ANY(...)` return NULL, which is indistinguishable from
	// "no match" here and would silently stop excluding anything.
	closed := make([]string, 0, len(windowClosedPolicies))
	for _, id := range windowClosedPolicies {
		closed = append(closed, id.String())
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
		       -- A cancelled scan stops being dispatched, not just stopped.
		       -- Without this, propagateCancellations halts the in-flight jobs
		       -- of a cancelled scan and offerWork hands out its remaining
		       -- queued ones two seconds later, forever. That is not a
		       -- cancellation; it is the same shape as the kill-switch clause
		       -- below, for the same reason.
		       AND NOT EXISTS (
		           SELECT 1 FROM scans s
		            WHERE s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		              AND s.status IN ('cancelled', 'killed')
		       )
		       AND NOT EXISTS (
		           SELECT 1 FROM kill_switches k
		            WHERE k.tenant_id = j.tenant_id
		              AND k.resolved_at IS NULL
		              -- All three scopes. 'zone' was missing, and the gap had
		              -- the same shape the comment above describes: a zone kill
		              -- halted that zone's in-flight work through
		              -- propagateKills and dispatch handed the same scan points
		              -- fresh jobs two seconds later, forever.
              -- NOT IN rather than = 'tenant' for the widest arm, so a
		              -- kill_scope a later migration adds blocks every claim
		              -- until someone teaches this predicate about it. The
		              -- fail-safe direction for a kill is too wide, never too
		              -- narrow.
		              AND (k.scope NOT IN ('zone', 'scan')
		                   OR (k.scope = 'scan' AND k.scope_scan_id = j.scan_id)
		                   OR (k.scope = 'zone' AND k.scope_zone_id =
		                       (SELECT sp.zone_id FROM scan_points sp
		                         WHERE sp.tenant_id = $1 AND sp.scan_point_id = $3)))
		       )
		       -- ADR-024 control 1, in the dimension the scan point cannot
		       -- lie about. allowed_zones names the vantage points a policy
		       -- permits, and until this clause existed a scan point in a
		       -- forbidden zone could claim the job: the column was selected by
		       -- nothing, so an operator restricting a scan to their DMZ had
		       -- written a comment. Zone comes from scan_points, never from the
		       -- stream.
		       --
		       -- An EMPTY allowed_zones is UNRESTRICTED, the opposite of
		       -- ScanConstraints.allowed_targets, and ADR-037 records why: this
		       -- list answers "is this scan restricted", and an unset
		       -- restriction is no restriction. Every policy row that exists
		       -- today defaults to '[]', so the other reading would have
		       -- stopped the fleet on the migration that enforced it.
		       --
		       -- jsonb_array_elements_text with lower() rather than the ?
		       -- operator or jsonb_exists. Two reasons, and both were real
		       -- defects. ? is a placeholder in several drivers, and a query
		       -- that changes meaning with the driver is not one to put an
		       -- authorisation decision in. And byte-exact matching means an
		       -- allowlist holding an UPPERCASE uuid matches nothing, because
		       -- zone_id::text renders lowercase canonical — an operator's zone
		       -- restriction silently becoming a restriction to no zone at all.
		       --
		       -- No ::uuid cast on the elements, deliberately: one malformed
		       -- entry would then raise and fail every claim in the TENANT
		       -- rather than just this policy's. Shape is validated at write
		       -- time instead, by a trigger in migration 0024.
		       --
		       -- The coalesce is fail-closed — a scan point with no resolvable
		       -- zone matches no allowlist rather than passing a NULL comparison
		       -- through as "not restricted".
		       AND NOT EXISTS (
		           SELECT 1 FROM scans s
		            JOIN scan_policies p
		              ON p.tenant_id = s.tenant_id AND p.policy_id = s.policy_id
		            WHERE s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		              AND jsonb_array_length(p.allowed_zones) > 0
		              AND NOT EXISTS (
		                  SELECT 1 FROM jsonb_array_elements_text(p.allowed_zones) z
		                   WHERE lower(z) = coalesce(
		                       (SELECT sp.zone_id::text FROM scan_points sp
		                         WHERE sp.tenant_id = $1 AND sp.scan_point_id = $3), '')
		              )
		       )
		       -- Outside its maintenance window, a job stays queued. Evaluated
		       -- in Go and passed in; see the doc comment above.
		       AND NOT EXISTS (
		           SELECT 1 FROM scans s
		            WHERE s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		              AND s.policy_id = ANY($6::uuid[])
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

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), names, scanPointID, limit, MaxAttempts, closed)
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
//
// EVERY task, whatever its status. The assignment is the whole job: a status
// filter here would hand a re-claimed reassign_safe job fewer targets than it
// has (ErrTooManyTasks's failure arrived at from the other side), stop
// scopeNarrowedForJob's mid-scan re-check covering the dropped targets, and
// make tasksBelongToJob refuse valid observations. Task status is a record of
// what happened, never a filter on what is sent.
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
	// The job's tasks follow it. Only the first progress report moves the job
	// (status = 'assigned' above), so this runs once per job.
	const tq = `
		UPDATE scan_tasks SET status = 'running', started_at = now()
		 WHERE tenant_id = $1 AND job_id = $2 AND status = 'pending'`
	_, err = c.Exec(ctx, tq, c.Tenant().UUID(), jobID)
	return mapError(err)
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
//
// incomplete is JobTerminal's flag: the scan point marked its results partial
// (ADR-026), so a completed reason does not mean every task was covered.
func (Jobs) Terminate(ctx context.Context, c *Conn, jobID, scanPointID uuid.UUID, reason TerminationReason, incomplete bool) error {
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

	// The job's tasks end with it, in the same transaction and only when the
	// job's own predicate matched — so a non-holder that cannot end the job
	// cannot end its tasks either. Nothing else ever advanced a task: every
	// task in the deploy estate sat at 'pending' under a completed job, and an
	// operator reads a pending task as work not yet done.
	otherwise := TaskFailed
	if status == JobCancelled || status == JobKilled {
		otherwise = TaskSkipped // stopped by an operator, not lost by an engine
	}
	return mapError(endTasks(ctx, c, jobID, status == JobCompleted && !incomplete, otherwise))
}

// TaskStatus is scan_tasks.status (migration 0005, task_status).
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskSkipped   TaskStatus = "skipped"
)

// endTasks closes a job's open tasks once the job itself has ended.
//
// The wire carries no per-task outcome — JobTerminal has tasks_completed and
// tasks_failed as COUNTS and one `incomplete` flag — so Core decides from what
// it holds. A job that completed with its results whole completed its tasks.
// Any other ending is judged task by task on the one thing Core can see:
// whether an observation was attributed to the task. The credentialed engine
// aborts the whole job on the first unreachable host after emitting for the
// hosts before it (ADR-093), and those hosts were read; a completed-but-
// incomplete submission dropped something, and the tasks it dropped are the
// ones with nothing attributed. "The engine never reported on this target"
// and "the target was done" must not share a status in either direction.
//
// `otherwise` is what an unreported task becomes: failed when the engine or
// the lease was lost — nothing here can tell "unreachable" from "never
// reached", and failed is the reading an operator investigates — and skipped
// when an operator stopped the job, because that target was not attempted.
//
// The observations read is bounded to the job's own window — nothing observed
// for a task predates its job — because observations is partitioned by
// observed_at and an unbounded EXISTS visits every live partition per task,
// inside the terminal's transaction (internal/store/CLAUDE.md).
func endTasks(ctx context.Context, c *Conn, jobID uuid.UUID, allCovered bool, otherwise TaskStatus) error {
	const q = `
		UPDATE scan_tasks t
		   SET status = CASE
		                  WHEN $3::bool THEN 'completed'::task_status
		                  WHEN EXISTS (SELECT 1 FROM observations o
		                                WHERE o.tenant_id = t.tenant_id AND o.task_id = t.task_id
		                                  AND o.ingest_state = 'accepted'
		                                  AND o.observed_at >= j.created_at - interval '1 hour')
		                       THEN 'completed'::task_status
		                  ELSE $4::task_status
		                END,
		       completed_at = now()
		  FROM scan_jobs j
		 WHERE j.tenant_id = t.tenant_id AND j.job_id = t.job_id
		   AND t.tenant_id = $1 AND t.job_id = $2 AND t.status IN ('pending', 'running')`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, allCovered, string(otherwise))
	return err
}

// ReconcileTasksWithResults revisits a job's ended tasks once a submission for
// it is promoted to accepted.
//
// Only ACCEPTED observations count as coverage, in endTasks and here: a pending
// row was never attested complete and a quarantined one is withheld from the
// pipeline, so neither says the target was done. That filter opens a window:
// the runtime submits before it sends JobTerminal, but the two travel on
// different streams, and a terminal that lands before the final chunk's ack
// judges tasks whose results are still in flight — failed, with nothing to
// revisit them. Ingest calls this after the promotion, so a task the terminal
// wrote off becomes completed the moment its results are accepted. Only FAILED
// tasks move: a skipped one was stopped by an operator (cancel, kill switch),
// and ADR-024 exists so the operator can see what was and was not finished —
// a target the engine had half-reported on before the halt stays skipped.
// Same window bound as endTasks.
func (Jobs) ReconcileTasksWithResults(ctx context.Context, c *Conn, jobID uuid.UUID) error {
	const q = `
		UPDATE scan_tasks t
		   SET status = 'completed', completed_at = now()
		  FROM scan_jobs j
		 WHERE j.tenant_id = t.tenant_id AND j.job_id = t.job_id
		   AND t.tenant_id = $1 AND t.job_id = $2 AND t.status = 'failed'
		   AND EXISTS (SELECT 1 FROM observations o
		                WHERE o.tenant_id = t.tenant_id AND o.task_id = t.task_id
		                  AND o.ingest_state = 'accepted'
		                  AND o.observed_at >= j.created_at - interval '1 hour')`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID)
	return mapError(err)
}

// ScanIDForTask names the scan a task belongs to — the OCCASION an identity
// key sighting is counted on (ADR-094).
func (Jobs) ScanIDForTask(ctx context.Context, c *Conn, taskID uuid.UUID) (uuid.UUID, error) {
	const q = `
		SELECT j.scan_id FROM scan_tasks t
		  JOIN scan_jobs j ON j.tenant_id = t.tenant_id AND j.job_id = t.job_id
		 WHERE t.tenant_id = $1 AND t.task_id = $2`
	var id uuid.UUID
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), taskID).Scan(&id); err != nil {
		return uuid.Nil, mapError(err)
	}
	return id, nil
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

// CancellableJob is one in-flight job whose scan an operator has stopped.
type CancellableJob struct {
	JobID  uuid.UUID
	Epoch  int64
	ScanID uuid.UUID

	// ScanStatus is 'cancelled' or 'killed'. It travels so the reason on the
	// wire and in the audit log says which one happened: an operator reading
	// "cancelled" about a scan they killed has been told something untrue about
	// their own action.
	ScanStatus ScanStatus
}

// CancellableFor lists jobs this scan point is running under a cancelled scan.
//
// ============================================================================
// ADR-024 control 4, and the half that is not the kill switch.
// ============================================================================
//
// A kill switch halts the fleet. Per-scan cancellation stops one runaway scan
// and leaves everything else running, and the difference matters because an
// operator with only the fleet-wide control will hesitate to use it — a stop
// button that costs every other customer's scan is a stop button people
// negotiate with rather than press.
//
// The trigger is scans.status, which already exists: an operator stops a SCAN,
// and every job under it that some scan point is still holding gets a CancelJob.
// No new column, and no second source of truth about whether something is
// stopped.
//
// Both stopped statuses, not just 'cancelled'. Jobs.Claim has excluded
// 'cancelled' and 'killed' from the outset, so a killed scan's queued jobs
// stopped being handed out while its IN-FLIGHT jobs were told nothing — the one
// state where the scan is most demonstrably still touching the estate. A scan is
// killed by an operator acting on a scan-scoped kill switch, and KillSwitch
// carries no job ids: this is the message that names them.
//
// The lease epoch travels because CancelJob must name the incarnation Core
// means, and the epoch selected is THIS scan point's — not the job's highest.
// After a reassignment the highest epoch belongs to somebody else, and a scan
// point told to cancel an incarnation it does not hold will correctly ignore the
// message.
//
// ============================================================================
// The criterion is the LEASE, not scan_jobs.scan_point_id.
// ============================================================================
//
// It was `scan_point_id = $2 AND status IN ('assigned','running')`, which drops
// the job at precisely the wrong moment. ExpireLeases nulls scan_point_id and
// requeues a reassign_safe job, or marks a non-reassign_safe one 'failed' — so a
// scan point that partitioned while scanning stops matching just as it becomes
// the thing an operator most needs to stop. It is still holding a lease and
// still sending packets; Core simply lost its own record of who to talk to.
//
// A lease reaching 'released' is the one signal that the scan point actually
// reported stopping; anything short of that and the cancellation is still owed.
// Bounded by StillHoldingGrace, because a lease that ExpireLeases has already
// moved out of 'granted' can never be released afterwards — see that constant.
// Re-sending a cancellation to a scan point that already halted is harmless;
// failing to send one is the whole failure ADR-024 control 4 exists to prevent.
func (Jobs) CancellableFor(ctx context.Context, c *Conn, scanPointID uuid.UUID) ([]CancellableJob, error) {
	const q = `
		SELECT j.job_id, l.epoch, j.scan_id, s.status
		  FROM scan_jobs j
		  JOIN scans s ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		  JOIN LATERAL (
		       SELECT epoch FROM job_leases
		        WHERE tenant_id = j.tenant_id AND job_id = j.job_id
		          AND holder_scan_point = $2
		          AND state <> 'released'
		          AND expires_at > now() - ` + StillHoldingGrace + `
		        ORDER BY epoch DESC LIMIT 1
		  ) l ON true
		 WHERE j.tenant_id = $1
		   AND s.status IN ('cancelled', 'killed')
		 ORDER BY j.created_at`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanPointID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []CancellableJob
	for rows.Next() {
		var j CancellableJob
		if err := rows.Scan(&j.JobID, &j.Epoch, &j.ScanID, &j.ScanStatus); err != nil {
			return nil, mapError(err)
		}
		out = append(out, j)
	}
	return out, mapError(rows.Err())
}
