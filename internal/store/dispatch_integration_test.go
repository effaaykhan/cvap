package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// seedJob creates the policy -> scan -> job chain and returns the job id.
func seedJob(t *testing.T, db *store.DB, tenant store.TenantID, scanPointID uuid.UUID, reassignSafe bool) uuid.UUID {
	t.Helper()
	var jobID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		suffix := uuid.NewString()[:8]

		var policyID, scanID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name) VALUES ($1,$2) RETURNING policy_id`,
			tid, "disp-"+suffix).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery')
			 RETURNING scan_id`, tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		// An AUTHORISED target, because Jobs.Claim now refuses a job whose tasks
		// do not trace to one. That refusal is the point — migration 0005 says
		// dispatch must not decompose an unauthorised target, and the old seed
		// created a task with a NULL target_id, so the test was demonstrating
		// the gap rather than the behaviour.
		var targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value,
			                           authorization_verified, verified_at)
			 VALUES ($1,$2,'cidr','192.0.2.0/24',true,now()) RETURNING target_id`,
			tid, scanID).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',$3) RETURNING job_id`,
			tid, scanID, reassignSafe).Scan(&jobID); err != nil {
			return err
		}
		// 192.0.2.0/24 is TEST-NET-1: reserved for documentation, never routed,
		// and already in lab/scope.txt. A fixture target outside lab scope is
		// inert today and a live target the moment a runtime exists.
		_, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
			 VALUES ($1,$2,$3,'192.0.2.1')`,
			tid, jobID, targetID)
		return err
	}); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	return jobID
}

// seedScanPoint creates a zone and an online scan point.
func seedScanPoint(t *testing.T, db *store.DB, tenant store.TenantID) uuid.UUID {
	t.Helper()
	var spID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "disp-zone-"+uuid.NewString()[:8], store.ZoneInternal, 50, "")
		if err != nil {
			return err
		}
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "sp", "0.1.0", "v1", "fp-"+uuid.NewString())
		if err != nil {
			return err
		}
		spID = sp.ID
		// Heartbeat rather than SetStatus: it sets last_heartbeat as well as
		// status, and Unacknowledged keys on the heartbeat. A scan point with a
		// status of 'online' and no heartbeat has never actually been reachable,
		// which is exactly the case that query now excludes.
		if err := (store.ScanPoints{}).Heartbeat(ctx, c, sp.ID, time.Now()); err != nil {
			return err
		}
		_, err = (store.ScanPoints{}).DeclareCapability(ctx, c, sp.ID, store.EngineDiscovery, "0.1.0", true)
		return err
	}); err != nil {
		t.Fatalf("seed scan point: %v", err)
	}
	return spID
}

// ============================================================================
// At-most-once, part 1: concurrent claim.
// ============================================================================
//
// SKIP LOCKED means a second dispatcher does not SEE a locked row rather than
// waiting on it and losing. Twelve dispatchers race for one job; exactly one may
// win, and the job's attempt count must be 1 — an attempt count of 12 would mean
// twelve transactions each incremented it before losing, which is a different
// bug that a "exactly one winner" assertion alone would miss.
func TestJobClaimedByExactlyOneDispatcher(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "claim-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, spID, false)

	const racers = 12
	var wg sync.WaitGroup
	claimed := make([][]store.Job, racers)
	errs := make([]error, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
				jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
				claimed[i] = jobs
				return err
			})
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i := range claimed {
		if errs[i] != nil {
			t.Errorf("dispatcher %d: %v", i, errs[i])
			continue
		}
		for _, j := range claimed[i] {
			if j.ID == jobID {
				winners++
			}
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d dispatchers claimed the same job; a job assigned twice is two "+
			"scan points doing the same work", winners, racers)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		j, err := (store.Jobs{}).GetByID(ctx, c, jobID)
		if err != nil {
			return err
		}
		if j.Status != store.JobAssigned {
			t.Errorf("job status %q, want assigned", j.Status)
		}
		if j.Attempt != 1 {
			t.Errorf("attempt = %d, want 1; a higher count means losing transactions "+
				"incremented it before rolling back", j.Attempt)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// At-most-once, part 2: the sweep. This is where it is actually won or lost.
// ============================================================================
//
// A concurrent-claim test passes against an implementation that re-queues every
// expired job, and that implementation duplicates active and intrusive work on a
// customer's estate. reassign_safe is the whole distinction (ADR-012).
func TestExpiredLeaseRequeuesOnlyReassignSafeJobs(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "sweep-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)

	safeJob := seedJob(t, db, tenant, spID, true)
	unsafeJob := seedJob(t, db, tenant, spID, false)

	// Assign both, lease both, then expire both leases by force.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		if len(jobs) != 2 {
			t.Fatalf("claimed %d jobs, want 2", len(jobs))
		}
		for _, j := range jobs {
			if _, err := (store.Leases{}).Grant(ctx, c, j.ID, spID, store.LeaseTTL); err != nil {
				return err
			}
		}
		// Backdate BOTH timestamps: job_leases_expiry_after_grant requires
		// expires_at > granted_at, so a lease cannot be expired by moving only
		// its expiry into the past. What an actually-expired lease looks like is
		// one granted a while ago that ran out since.
		_, err = c.Exec(ctx,
			`UPDATE job_leases
			    SET granted_at = clock_timestamp() - interval '2 minutes',
			        expires_at = clock_timestamp() - interval '1 minute'
			  WHERE tenant_id = $1`, c.Tenant().UUID())
		return err
	}); err != nil {
		t.Fatalf("assign and expire: %v", err)
	}

	var expired []store.ExpiredLease
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		expired, err = (store.Leases{}).ExpireLeases(ctx, c, 100)
		return err
	}); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(expired) != 2 {
		t.Fatalf("swept %d expired leases, want 2", len(expired))
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		safe, err := (store.Jobs{}).GetByID(ctx, c, safeJob)
		if err != nil {
			return err
		}
		unsafe, err := (store.Jobs{}).GetByID(ctx, c, unsafeJob)
		if err != nil {
			return err
		}

		// reassign_safe: back in the queue, unassigned, so another scan point
		// can pick it up. Dedup absorbs the overlap (ADR-010).
		if safe.Status != store.JobQueued {
			t.Errorf("reassign_safe job is %q, want queued", safe.Status)
		}
		if safe.ScanPointID != nil {
			t.Error("a requeued job still names a scan point; it would not be claimable")
		}

		// NOT reassign_safe: failed loudly, never requeued. Duplicating active
		// or intrusive work harms the target, so this escalates to an operator
		// rather than retrying (ADR-012).
		if unsafe.Status != store.JobFailed {
			t.Errorf("non-reassign_safe job is %q, want failed; re-queuing it would "+
				"duplicate active work against a customer's estate", unsafe.Status)
		}
		if unsafe.TerminationReason == nil || *unsafe.TerminationReason != store.TerminationLeaseLost {
			t.Errorf("non-reassign_safe job termination_reason = %v, want lease_lost",
				unsafe.TerminationReason)
		}
		if unsafe.CompletedAt == nil {
			t.Error("a failed job has no completed_at; the operator cannot see when it died")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// And the failed job must not be claimable again.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			if j.ID == unsafeJob {
				t.Error("a failed non-reassign_safe job was claimed again")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// Lease fencing: renewal against a superseded epoch.
// ============================================================================
//
// Forced interleaving rather than a sequential check. T1 holds epoch 1 and is
// about to renew; a reassignment issues epoch 2 and commits first; T1's renewal
// must then find nothing — because it re-evaluates state = 'granted' against the
// updated row after the lock wait, not against the snapshot it started with.
func TestRenewalRefusedAfterSupersession(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "fence-"+uuid.NewString()[:8])
	spA := seedScanPoint(t, db, tenant)
	spB := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, spA, true)

	var epoch1 int64
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Jobs{}).Claim(ctx, c, spA, []store.Engine{store.EngineDiscovery}, 10); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, jobID, spA, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch1 = l.Epoch
		return nil
	}); err != nil {
		t.Fatalf("first grant: %v", err)
	}

	// Renewal at the current epoch works.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Leases{}).Renew(ctx, c, jobID, epoch1, spA, store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatalf("renewal at the current epoch was refused: %v", err)
	}

	// Reassignment: mark the old lease lost and issue a higher epoch, one
	// transaction — which is what makes a concurrent renewal fail.
	var epoch2 int64
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).ReleaseAny(ctx, c, jobID, epoch1, store.LeaseLost); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, jobID, spB, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch2 = l.Epoch
		return nil
	}); err != nil {
		t.Fatalf("reassignment: %v", err)
	}
	if epoch2 <= epoch1 {
		t.Fatalf("reassignment issued epoch %d, not higher than %d; the epoch is not a "+
			"fencing token if it does not increase", epoch2, epoch1)
	}

	// The superseded holder's renewal is refused.
	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Leases{}).Renew(ctx, c, jobID, epoch1, spA, store.LeaseTTL)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("renewal at a superseded epoch: got %v, want ErrNotFound", err)
	}

	// And so is one from the wrong holder at the RIGHT epoch — the
	// holder_scan_point predicate, without which one scan point could renew
	// another's lease.
	err = db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Leases{}).Renew(ctx, c, jobID, epoch2, spA, store.LeaseTTL)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("renewal by a non-holder at the current epoch: got %v, want ErrNotFound. "+
			"Without the holder predicate this is a fencing bypass that looks like a "+
			"liveness message", err)
	}

	// The real holder can still renew.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Leases{}).Renew(ctx, c, jobID, epoch2, spB, store.LeaseTTL)
		return err
	}); err != nil {
		t.Errorf("the current holder could not renew: %v", err)
	}
}

// An expired lease is not renewable, even at the right epoch by the right
// holder. A reassignment may already be in flight, and extending it would put
// two scan points on one job.
func TestExpiredLeaseCannotBeRenewed(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "expiry-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, spID, true)

	var epoch int64
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch = l.Epoch
		// Both timestamps; see the note in the sweep test.
		_, err = c.Exec(ctx,
			`UPDATE job_leases
			    SET granted_at = clock_timestamp() - interval '2 minutes',
			        expires_at = clock_timestamp() - interval '1 minute'
			  WHERE tenant_id = $1 AND job_id = $2 AND epoch = $3`,
			c.Tenant().UUID(), jobID, epoch)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Leases{}).Renew(ctx, c, jobID, epoch, spID, store.LeaseTTL)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("renewing an expired lease: got %v, want ErrNotFound", err)
	}
}

// Epochs are monotonic per job and never reused.
func TestEpochsAreMonotonic(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "epoch-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, spID, true)

	var last int64
	for i := 0; i < 5; i++ {
		if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			if last > 0 {
				if err := (store.Leases{}).ReleaseAny(ctx, c, jobID, last, store.LeaseExpired); err != nil {
					return err
				}
			}
			l, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
			if err != nil {
				return err
			}
			if l.Epoch <= last {
				t.Errorf("epoch %d did not increase from %d", l.Epoch, last)
			}
			last = l.Epoch
			return nil
		}); err != nil {
			t.Fatalf("grant %d: %v", i, err)
		}
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		cur, err := (store.Leases{}).Current(ctx, c, jobID)
		if err != nil {
			return err
		}
		if cur.Epoch != last {
			t.Errorf("Current returned epoch %d, want the highest %d", cur.Epoch, last)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The kill switch bound is measurable: who has not acknowledged is a query.
func TestKillAcknowledgementIsMeasurable(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "kill-"+uuid.NewString()[:8])
	spA := seedScanPoint(t, db, tenant)
	spB := seedScanPoint(t, db, tenant)

	var killID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		k, err := (store.KillSwitches{}).Issue(ctx, c, store.KillTenant, nil, nil, nil, "test halt")
		if err != nil {
			return err
		}
		killID = k.ID
		return nil
	}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.KillSwitches{}).Unacknowledged(ctx, c, killID)
		if err != nil {
			return err
		}
		if len(un) != 2 {
			t.Errorf("%d scan points unacknowledged immediately after issue, want 2", len(un))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A acks, twice — the second must be a no-op, or the count stops meaning
	// anything.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.KillSwitches{}).Ack(ctx, c, killID, spA, 3); err != nil {
			return err
		}
		return (store.KillSwitches{}).Ack(ctx, c, killID, spA, 3)
	}); err != nil {
		t.Fatalf("ack: %v", err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.KillSwitches{}).Unacknowledged(ctx, c, killID)
		if err != nil {
			return err
		}
		if len(un) != 1 || un[0] != spB {
			t.Errorf("unacknowledged = %v, want exactly [%s]", un, spB)
		}
		var acks int
		if err := c.QueryRow(ctx,
			`SELECT count(*) FROM kill_acks WHERE tenant_id = $1 AND kill_id = $2`,
			tenant.UUID(), killID).Scan(&acks); err != nil {
			return err
		}
		if acks != 1 {
			t.Errorf("%d ack rows after a duplicate ack, want 1", acks)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

}

// ============================================================================
// Regressions from the scan-safety audit.
// ============================================================================

// A live kill switch stops job assignment.
//
// Without this, propagateKills halts the fleet's in-flight work and offerWork
// hands out fresh jobs two seconds later, forever — Core telling scan points to
// stop and then giving them something new to do. Found by scan-safety-auditor.
func TestLiveKillSwitchStopsAssignment(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "killstop-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)
	seedJob(t, db, tenant, spID, true)

	var killID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		k, err := (store.KillSwitches{}).Issue(ctx, c, store.KillTenant, nil, nil, nil, "halt")
		if err != nil {
			return err
		}
		killID = k.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		if len(jobs) != 0 {
			t.Errorf("claimed %d jobs while a kill switch was live", len(jobs))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// And resolving it lets work flow again — a control with no off switch is
	// an outage with extra steps.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.KillSwitches{}).Resolve(ctx, c, killID)
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		if len(jobs) != 1 {
			t.Errorf("claimed %d jobs after the kill was resolved, want 1", len(jobs))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Dispatch refuses a job whose target is not authorised.
//
// Migration 0005 says outright that dispatch must not decompose a target where
// authorization_verified is false, and execution-plan §8 risk 6 calls an
// unauthorised scan legal exposure. Dispatch is the last Core-side component
// before a target leaves Core, so if the check is not here it is nowhere.
func TestUnauthorisedTargetsAreNeverAssigned(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "authz-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)

	var unverified, orphan uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		var policyID, scanID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name) VALUES ($1,$2) RETURNING policy_id`,
			tid, "authz-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery')
			 RETURNING scan_id`, tid, policyID).Scan(&scanID); err != nil {
			return err
		}

		// A target explicitly NOT authorised.
		var targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value,
			                           authorization_verified)
			 VALUES ($1,$2,'cidr','192.0.2.0/24',false) RETURNING target_id`,
			tid, scanID).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',true) RETURNING job_id`,
			tid, scanID).Scan(&unverified); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
			 VALUES ($1,$2,$3,'192.0.2.9')`, tid, unverified, targetID); err != nil {
			return err
		}

		// A task with no target at all: no authorisation record exists, so
		// there is nothing that could have been verified.
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',true) RETURNING job_id`,
			tid, scanID).Scan(&orphan); err != nil {
			return err
		}
		_, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, task_target) VALUES ($1,$2,'192.0.2.10')`,
			tid, orphan)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			if j.ID == unverified {
				t.Error("assigned a job whose target has authorization_verified = false")
			}
			if j.ID == orphan {
				t.Error("assigned a job whose task traces to no target at all")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// fragile reaches the wire. ADR-024 control 3 caps rate on a fragile device
// regardless of policy, and fragile_rate_pps on the constraints is decorative
// unless the runtime is told which task it applies to.
func TestFragileTravelsFromAssetToTask(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "fragile-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, spID, true)

	// Before: no asset, so not fragile — the permissive default, chosen because
	// treating unknown as fragile would throttle every discovery scan.
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		tasks, err := (store.Jobs{}).Tasks(ctx, c, jobID)
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].Fragile {
			t.Errorf("a task with no asset reports fragile=%v, want false", tasks[0].Fragile)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Attach a fragile asset, as correlation would.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "delicate", Fragile: true})
		if err != nil {
			return err
		}
		tasks, err := (store.Jobs{}).Tasks(ctx, c, jobID)
		if err != nil {
			return err
		}
		_, err = c.Exec(ctx,
			`UPDATE scan_tasks SET asset_id = $3 WHERE tenant_id = $1 AND task_id = $2`,
			c.Tenant().UUID(), tasks[0].ID, a.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		tasks, err := (store.Jobs{}).Tasks(ctx, c, jobID)
		if err != nil {
			return err
		}
		if !tasks[0].Fragile {
			t.Error("a task targeting a fragile asset reports fragile=false; the rate cap " +
				"would never reach the send path")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The kill bound is measured, not just observed. ADR-024: "a 10-second bound
// Core cannot measure is not a control" — a set of who is missing does not
// measure a bound.
func TestKillAckLatencyIsMeasured(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "latency-"+uuid.NewString()[:8])
	spID := seedScanPoint(t, db, tenant)

	var killID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		k, err := (store.KillSwitches{}).Issue(ctx, c, store.KillTenant, nil, nil, nil, "halt")
		if err != nil {
			return err
		}
		killID = k.ID
		return (store.KillSwitches{}).Ack(ctx, c, killID, spID, 1)
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		lat, err := (store.KillSwitches{}).AckLatency(ctx, c, killID)
		if err != nil {
			return err
		}
		if len(lat) != 1 {
			t.Fatalf("%d latencies, want 1", len(lat))
		}
		if lat[0].ScanPointID != spID {
			t.Errorf("latency reported for %s, want %s", lat[0].ScanPointID, spID)
		}
		if lat[0].Latency > 10*time.Second {
			t.Errorf("ack latency %s exceeds ADR-024's 10s bound", lat[0].Latency)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestTasksRefusesAJobTooLargeForOneAssignment covers the direction that would
// otherwise be invisible.
//
// A LIMIT that trimmed the task set would produce a job the scan point completes
// successfully while never touching the remaining targets: the scan reports done
// and coverage is short, with nothing anywhere saying so. That is under-scanning
// that looks like a clean run, and the customer acts on it.
func TestTasksRefusesAJobTooLargeForOneAssignment(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "oversize")
	spID := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, spID, true)

	// seedJob leaves one task. Add enough to cross the cap, reusing its target so
	// the job stays authorised and Claim's refusal is not what fails the test.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `
			INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
			SELECT $1, $2,
			       (SELECT target_id FROM scan_tasks WHERE tenant_id = $1 AND job_id = $2 LIMIT 1),
			       '192.0.2.' || (g % 254 + 1)
			  FROM generate_series(1, $3) AS g`,
			c.Tenant().UUID(), jobID, store.MaxTasksPerAssignment)
		return err
	}); err != nil {
		t.Fatalf("seed tasks: %v", err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tasks, err := (store.Jobs{}).Tasks(ctx, c, jobID)
		if !errors.Is(err, store.ErrTooManyTasks) {
			t.Errorf("Tasks on a %d-task job returned %d tasks and error %v; want ErrTooManyTasks. "+
				"Silently returning the first %d is a job that completes with targets it never "+
				"reached.", store.MaxTasksPerAssignment+1, len(tasks), err,
				store.MaxTasksPerAssignment)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCancelledScanIsNeitherDispatchedNorLeftRunning is ADR-024 control 4.
//
// Both halves, because either alone is not a cancellation. Stopping the
// in-flight jobs while offerWork hands out the scan's remaining queued ones two
// seconds later is the same failure the kill switch had; refusing to dispatch
// while the running job continues is the other half of it.
func TestCancelledScanIsNeitherDispatchedNorLeftRunning(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "cancel")
	spID := seedScanPoint(t, db, tenant)

	running := seedJob(t, db, tenant, spID, true)
	var scanID uuid.UUID
	var epoch int64

	// Take one job and lease it, then queue a second under the SAME scan so the
	// dispatch half has something to refuse.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, running, spID, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch = l.Epoch

		j, err := (store.Jobs{}).GetByID(ctx, c, running)
		if err != nil {
			return err
		}
		scanID = j.ScanID

		var queued uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',true) RETURNING job_id`,
			c.Tenant().UUID(), scanID).Scan(&queued); err != nil {
			return err
		}
		_, err = c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
			 SELECT $1, $2, target_id, '192.0.2.2' FROM scan_tasks
			  WHERE tenant_id = $1 AND job_id = $3 LIMIT 1`,
			c.Tenant().UUID(), queued, running)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Nothing is cancellable yet, and the queued job is claimable.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 0 {
			t.Errorf("control: %d cancellable jobs before the scan was cancelled, want 0", len(pending))
		}
		claimed, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		if len(claimed) != 1 {
			t.Errorf("control: claimed %d jobs from a live scan, want 1 — if this is 0 the "+
				"test below proves nothing", len(claimed))
		}
		// Put it back so the post-cancellation claim has something to refuse.
		_, err = c.Exec(ctx, `UPDATE scan_jobs SET status = 'queued', scan_point_id = NULL
		                       WHERE tenant_id = $1 AND scan_id = $2 AND job_id <> $3`,
			c.Tenant().UUID(), scanID, running)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE scans SET status = 'cancelled'
		                        WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), scanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		// Half one: the in-flight job is cancellable, and carries the epoch, so
		// CancelJob names the incarnation Core means rather than whatever is
		// running under that job id after a reassignment.
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 1 {
			t.Fatalf("cancellable jobs = %d, want 1", len(pending))
		}
		if pending[0].JobID != running {
			t.Errorf("cancellable job = %v, want the leased one %v", pending[0].JobID, running)
		}
		if pending[0].Epoch != epoch {
			t.Errorf("cancellable job epoch = %d, want the current lease epoch %d",
				pending[0].Epoch, epoch)
		}

		// Half two: the scan's remaining queued work stops being handed out.
		claimed, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10)
		if err != nil {
			return err
		}
		if len(claimed) != 0 {
			t.Errorf("claimed %d jobs from a cancelled scan, want 0. Halting in-flight work "+
				"while dispatching the rest two seconds later is not a cancellation.",
				len(claimed))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
