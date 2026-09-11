package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// A job's tasks follow the job (ADR-093 decision 3). Before S42 nothing wrote
// scan_tasks.status at all: every task in the deploy estate sat at 'pending'
// under a completed job, on every scan, and an operator reads a pending task as
// work not yet done.
//
// The wire carries no per-task outcome, so Core judges from what it holds:
//
//   - a job that completed with its results whole completes every task;
//   - any other ending — engine failure, completed-but-incomplete, lease loss —
//     completes the tasks that have an observation attributed and fails the
//     rest, because "never reported on" and "done" must not share a status in
//     either direction;
//   - a cancel or kill leaves unreported tasks skipped, not failed: an operator
//     stopped them, no engine lost them;
//   - a re-queued reassign_safe job takes its tasks back to pending.
//
// Every write rides the job's own holder predicate: a non-holder's Terminate
// matches no job row and returns before touching tasks
// (TestTerminateRefusesANonHolder covers the job half; a block here covers the
// task half).
func TestTasksFollowTheirJobThroughRunningAndTerminal(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "tasks-"+uuid.NewString()[:8])
	holder := seedScanPoint(t, db, tenant)
	other := seedScanPoint(t, db, tenant)

	claim := func(jobID uuid.UUID) {
		t.Helper()
		if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			jobs, err := (store.Jobs{}).Claim(ctx, c, holder, []store.Engine{store.EngineDiscovery}, 10, nil)
			if err != nil {
				return err
			}
			for _, j := range jobs {
				if j.ID == jobID {
					return nil
				}
			}
			t.Fatalf("claim did not return job %s", jobID)
			return nil
		}); err != nil {
			t.Fatalf("claim: %v", err)
		}
	}
	// status by task target, plus whether started_at / completed_at are set on
	// the first task (every seed's first task is 192.0.2.1).
	tasks := func(jobID uuid.UUID) (byTarget map[string]string, started, completed bool) {
		t.Helper()
		byTarget = map[string]string{}
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			rows, err := c.Query(ctx,
				`SELECT task_target, status::text, started_at IS NOT NULL, completed_at IS NOT NULL
				   FROM scan_tasks WHERE tenant_id = $1 AND job_id = $2 ORDER BY task_target`,
				c.Tenant().UUID(), jobID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var target, st string
				var s, cpl bool
				if err := rows.Scan(&target, &st, &s, &cpl); err != nil {
					return err
				}
				byTarget[target] = st
				if target == "192.0.2.1" {
					started, completed = s, cpl
				}
			}
			return rows.Err()
		}); err != nil {
			t.Fatalf("read tasks: %v", err)
		}
		return byTarget, started, completed
	}
	terminate := func(jobID, sp uuid.UUID, reason store.TerminationReason, incomplete bool) error {
		return db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return (store.Jobs{}).Terminate(ctx, c, jobID, sp, reason, incomplete)
		})
	}
	// A second task on the job, and an observation attributed to the FIRST —
	// the shape the credentialed engine leaves when it reads one host and
	// aborts on the next (ADR-093).
	addTaskAndObserveFirst := func(jobID uuid.UUID, state string) {
		t.Helper()
		if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			tid := c.Tenant().UUID()
			if _, err := c.Exec(ctx,
				`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
				 SELECT $1, $2, target_id, '192.0.2.2' FROM scan_tasks WHERE tenant_id = $1 AND job_id = $2 LIMIT 1`,
				tid, jobID); err != nil {
				return err
			}
			var taskID, zoneID uuid.UUID
			if err := c.QueryRow(ctx,
				`SELECT task_id FROM scan_tasks WHERE tenant_id = $1 AND job_id = $2 AND task_target = '192.0.2.1'`,
				tid, jobID).Scan(&taskID); err != nil {
				return err
			}
			if err := c.QueryRow(ctx,
				`SELECT zone_id FROM scan_points WHERE tenant_id = $1 AND scan_point_id = $2`,
				tid, holder).Scan(&zoneID); err != nil {
				return err
			}
			sub := "sub-" + uuid.NewString()[:8]
			if _, err := c.Exec(ctx,
				`INSERT INTO result_submissions (tenant_id, submission_id, job_id, lease_epoch, status)
				 VALUES ($1, $2, $3, 1, 'accepted')`, tid, sub, jobID); err != nil {
				return err
			}
			_, err := c.Exec(ctx,
				`INSERT INTO observations (observation_id, tenant_id, submission_id, task_id, scan_point_id, zone_id,
				                           observation_type, payload, observed_at, ingest_state)
				 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'host', '{"address":"192.0.2.1"}', now(), $6::observation_ingest_state)`,
				tid, sub, taskID, holder, zoneID, state)
			return err
		}); err != nil {
			t.Fatalf("add task and observation: %v", err)
		}
	}

	// Completed, results whole: pending -> running -> completed on every task.
	done := seedJob(t, db, tenant, holder, false)
	claim(done)
	if st, _, _ := tasks(done); st["192.0.2.1"] != "pending" {
		t.Fatalf("after claim: task status = %q, want pending", st["192.0.2.1"])
	}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Jobs{}).MarkRunning(ctx, c, done, holder)
	}); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if st, started, completed := tasks(done); st["192.0.2.1"] != "running" || !started || completed {
		t.Fatalf("after MarkRunning: status=%q started=%v completed=%v, want running/true/false", st["192.0.2.1"], started, completed)
	}
	if err := terminate(done, holder, store.TerminationCompleted, false); err != nil {
		t.Fatalf("terminate completed: %v", err)
	}
	if st, _, completed := tasks(done); st["192.0.2.1"] != "completed" || !completed {
		t.Fatalf("after Terminate(completed): status=%q completed=%v, want completed/true", st["192.0.2.1"], completed)
	}

	// Engine failure after one host was read: the read host is completed, the
	// unreported one failed — straight from pending, since a job can end before
	// it ever reported progress.
	partial := seedJob(t, db, tenant, holder, false)
	claim(partial)
	addTaskAndObserveFirst(partial, "accepted")
	if err := terminate(partial, holder, store.TerminationEngineFailure, false); err != nil {
		t.Fatalf("terminate failed: %v", err)
	}
	if st, _, _ := tasks(partial); st["192.0.2.1"] != "completed" || st["192.0.2.2"] != "failed" {
		t.Fatalf("after engine failure with one host read: %v, want 192.0.2.1 completed, 192.0.2.2 failed", st)
	}

	// Completed but marked incomplete (ADR-026): same task-by-task judgement.
	// A job-level "completed" must not stamp every target as covered when the
	// scan point itself said the results were partial.
	incomplete := seedJob(t, db, tenant, holder, false)
	claim(incomplete)
	addTaskAndObserveFirst(incomplete, "accepted")
	if err := terminate(incomplete, holder, store.TerminationCompleted, true); err != nil {
		t.Fatalf("terminate completed+incomplete: %v", err)
	}
	if st, _, _ := tasks(incomplete); st["192.0.2.1"] != "completed" || st["192.0.2.2"] != "failed" {
		t.Fatalf("after completed+incomplete: %v, want 192.0.2.1 completed, 192.0.2.2 failed", st)
	}

	// Cancelled by an operator: the unreported target was skipped, not lost.
	cancelled := seedJob(t, db, tenant, holder, false)
	claim(cancelled)
	if err := terminate(cancelled, holder, store.TerminationCancelled, false); err != nil {
		t.Fatalf("terminate cancelled: %v", err)
	}
	if st, _, _ := tasks(cancelled); st["192.0.2.1"] != "skipped" {
		t.Fatalf("after cancel: status=%q, want skipped", st["192.0.2.1"])
	}

	// Only ACCEPTED observations are coverage. A pending row was never attested
	// complete, so the task it hangs on is still failed after the terminal.
	unattested := seedJob(t, db, tenant, holder, false)
	claim(unattested)
	addTaskAndObserveFirst(unattested, "pending")
	if err := terminate(unattested, holder, store.TerminationEngineFailure, false); err != nil {
		t.Fatalf("terminate with pending results: %v", err)
	}
	if st, _, _ := tasks(unattested); st["192.0.2.1"] != "failed" {
		t.Fatalf("task with only a pending observation after terminal: %q, want failed", st["192.0.2.1"])
	}

	// Results that land AFTER the terminal — the two travel on different
	// streams — revisit the tasks the terminal wrote off. Ingest calls this
	// after promoting the submission.
	late := seedJob(t, db, tenant, holder, false)
	claim(late)
	if err := terminate(late, holder, store.TerminationEngineFailure, false); err != nil {
		t.Fatalf("terminate before results: %v", err)
	}
	if st, _, _ := tasks(late); st["192.0.2.1"] != "failed" {
		t.Fatalf("before results: %q, want failed", st["192.0.2.1"])
	}
	addTaskAndObserveFirst(late, "accepted")
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Jobs{}).ReconcileTasksWithResults(ctx, c, late)
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if st, _, _ := tasks(late); st["192.0.2.1"] != "completed" || st["192.0.2.2"] != "pending" {
		t.Fatalf("after late results: %v, want 192.0.2.1 completed and the later-added 192.0.2.2 untouched", st)
	}

	// A non-holder cannot end the job, and so cannot end its tasks.
	held := seedJob(t, db, tenant, holder, false)
	claim(held)
	if err := terminate(held, other, store.TerminationCompleted, false); err == nil {
		t.Fatal("non-holder Terminate succeeded")
	}
	if st, _, completed := tasks(held); st["192.0.2.1"] != "pending" || completed {
		t.Fatalf("after non-holder Terminate: status=%q completed=%v, want pending/false", st["192.0.2.1"], completed)
	}
}

// Lease loss is the other door a job ends through (ADR-012), and the one that
// surfaces to an operator; ExpireLeases ends or re-queues the tasks with it.
func TestTasksFollowTheirJobThroughLeaseLoss(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "lease-tasks-"+uuid.NewString()[:8])
	holder := seedScanPoint(t, db, tenant)

	fixed := seedJob(t, db, tenant, holder, false) // fails on lease loss
	safe := seedJob(t, db, tenant, holder, true)   // re-queues on lease loss

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, holder, []store.Engine{store.EngineDiscovery}, 10, nil)
		if err != nil {
			return err
		}
		if len(jobs) != 2 {
			t.Fatalf("claimed %d jobs, want 2", len(jobs))
		}
		for _, j := range jobs {
			if _, err := (store.Leases{}).Grant(ctx, c, j.ID, holder, 60*1e9); err != nil {
				return err
			}
			// Progress was seen, so the tasks are running when the lease dies.
			if err := (store.Jobs{}).MarkRunning(ctx, c, j.ID, holder); err != nil {
				return err
			}
		}
		// Backdate both timestamps (job_leases_expiry_after_grant).
		_, err = c.Exec(ctx,
			`UPDATE job_leases
			    SET granted_at = clock_timestamp() - interval '2 minutes',
			        expires_at = clock_timestamp() - interval '1 minute'
			  WHERE tenant_id = $1`, c.Tenant().UUID())
		return err
	}); err != nil {
		t.Fatalf("assign and expire: %v", err)
	}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		expired, err := (store.Leases{}).ExpireLeases(ctx, c, 100)
		if err == nil && len(expired) != 2 {
			t.Fatalf("expired %d leases, want 2", len(expired))
		}
		return err
	}); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	read := func(jobID uuid.UUID) (job, task string, started, completed bool) {
		t.Helper()
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx,
				`SELECT j.status::text, t.status::text, t.started_at IS NOT NULL, t.completed_at IS NOT NULL
				   FROM scan_jobs j JOIN scan_tasks t ON t.tenant_id = j.tenant_id AND t.job_id = j.job_id
				  WHERE j.tenant_id = $1 AND j.job_id = $2`,
				c.Tenant().UUID(), jobID).Scan(&job, &task, &started, &completed)
		}); err != nil {
			t.Fatalf("read: %v", err)
		}
		return
	}
	if job, task, _, completed := read(fixed); job != "failed" || task != "failed" || !completed {
		t.Fatalf("non-reassign_safe after lease loss: job=%s task=%s completed=%v, want failed/failed/true", job, task, completed)
	}
	if job, task, started, completed := read(safe); job != "queued" || task != "pending" || started || completed {
		t.Fatalf("reassign_safe after lease loss: job=%s task=%s started=%v completed=%v, want queued/pending/false/false",
			job, task, started, completed)
	}
}
