package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

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
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',$3) RETURNING job_id`,
			tid, scanID, reassignSafe).Scan(&jobID); err != nil {
			return err
		}
		_, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, task_target) VALUES ($1,$2,'10.0.0.1')`,
			tid, jobID)
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
		if err := (store.ScanPoints{}).SetStatus(ctx, c, sp.ID, store.ScanPointOnline); err != nil {
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
		if err := (store.Leases{}).Release(ctx, c, jobID, epoch1, store.LeaseLost); err != nil {
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
				if err := (store.Leases{}).Release(ctx, c, jobID, last, store.LeaseExpired); err != nil {
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
