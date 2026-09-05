package dispatch_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/dispatch"
	"github.com/effaaykhan/cvap/internal/store"
)

// leaseFor grants a lease on a fresh job and returns both ids plus the epoch.
func leaseFor(t *testing.T, db *store.DB, tenant store.TenantID, spID uuid.UUID, reassignSafe bool) (uuid.UUID, int64) {
	t.Helper()
	jobID := seedQueuedJob(t, db, tenant, reassignSafe)

	var epoch int64
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10, nil); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch = l.Epoch
		return nil
	}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	return jobID, epoch
}

// backdateLease makes a lease look like one nobody renewed.
//
// granted_at moves with expires_at because job_leases_expiry_after_grant checks
// the pair; backdating only the expiry violates the constraint and the test
// fails for a reason that has nothing to do with what it is testing.
func backdateLease(t *testing.T, db *store.DB, tenant store.TenantID, jobID uuid.UUID, age time.Duration) {
	t.Helper()
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `
			UPDATE job_leases
			   SET granted_at = now() - $3::interval - interval '1 minute',
			       expires_at = now() - $3::interval
			 WHERE tenant_id = $1 AND job_id = $2`,
			tenant.UUID(), jobID, age.String())
		return err
	}); err != nil {
		t.Fatalf("backdate lease: %v", err)
	}
}

func jobRow(t *testing.T, db *store.DB, tenant store.TenantID, jobID uuid.UUID) *store.Job {
	t.Helper()
	var j *store.Job
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		j, err = (store.Jobs{}).GetByID(ctx, c, jobID)
		return err
	}); err != nil {
		t.Fatalf("read job: %v", err)
	}
	return j
}

func newSweeper(t *testing.T, db *store.DB) *dispatch.Sweeper {
	t.Helper()
	return dispatch.NewSweeper(db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

// ============================================================================
// The finding this file exists for: ExpireLeases had no caller at all.
// ============================================================================

// TestSweeperRequeuesOnlyReassignSafeJobs is the at-most-once property from the
// other side. Jobs.Claim guarantees no job goes to two scan points at once; this
// guarantees a job whose holder died does not silently go to a second one.
//
// Both jobs are set up identically and expire identically. reassign_safe is the
// only difference between them, and it must be the only thing that decides.
func TestSweeperRequeuesOnlyReassignSafeJobs(t *testing.T) {
	db := testDB(t)
	tenant, _, spID := enrolledScanPoint(t, db)

	safeJob, _ := leaseFor(t, db, tenant, spID, true)
	unsafeJob, _ := leaseFor(t, db, tenant, spID, false)
	backdateLease(t, db, tenant, safeJob, time.Minute)
	backdateLease(t, db, tenant, unsafeJob, time.Minute)

	newSweeper(t, db).Sweep(context.Background())

	safe := jobRow(t, db, tenant, safeJob)
	if safe.Status != store.JobQueued {
		t.Errorf("reassign_safe job status %q after sweep, want %q — a job whose holder died "+
			"and which is safe to re-run must go back to the queue",
			safe.Status, store.JobQueued)
	}
	if safe.ScanPointID != nil {
		t.Errorf("reassign_safe job still points at scan point %v after requeue; a queued job "+
			"with a holder is claimable by nobody", *safe.ScanPointID)
	}

	unsafe := jobRow(t, db, tenant, unsafeJob)
	if unsafe.Status != store.JobFailed {
		t.Errorf("non-reassign_safe job status %q after sweep, want %q. Re-running active or "+
			"intrusive work harms the target, so ADR-012 makes this an operator escalation "+
			"rather than a retry.", unsafe.Status, store.JobFailed)
	}
	if unsafe.TerminationReason == nil || *unsafe.TerminationReason != store.TerminationLeaseLost {
		t.Errorf("non-reassign_safe job termination_reason %v, want lease_lost",
			unsafe.TerminationReason)
	}
	if unsafe.CompletedAt == nil {
		t.Error("non-reassign_safe job has no completed_at; a failed job that never completed " +
			"stays in every in-flight view forever")
	}

	// The escalation, not just the state change. A job marked failed with
	// nothing telling an operator to look at it is a scan that stopped halfway
	// against a customer's estate and nobody knows.
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		events, err := (store.AuditEvents{}).ListByResource(ctx, c, "scan_job", unsafeJob, 10)
		if err != nil {
			return err
		}
		var found bool
		for _, e := range events {
			if e.Action == "job.lease_lost" {
				found = true
			}
		}
		if !found {
			t.Errorf("no job.lease_lost audit event for the non-reassign_safe job; got %d events",
				len(events))
		}

		events, err = (store.AuditEvents{}).ListByResource(ctx, c, "scan_job", safeJob, 10)
		if err != nil {
			return err
		}
		for _, e := range events {
			if e.Action == "job.lease_lost" {
				t.Error("a routine requeue raised an operator escalation; an alert that fires " +
					"on ordinary reassignment is an alert that gets muted")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSweeperLeavesLiveLeasesAlone is the other half, and the one that would
// make the sweeper dangerous if it were wrong: expiring a lease that has not
// expired hands a live scan point's job to somebody else.
func TestSweeperLeavesLiveLeasesAlone(t *testing.T) {
	db := testDB(t)
	tenant, _, spID := enrolledScanPoint(t, db)
	jobID, epoch := leaseFor(t, db, tenant, spID, true)

	newSweeper(t, db).Sweep(context.Background())

	if got := jobRow(t, db, tenant, jobID); got.Status != store.JobAssigned {
		t.Errorf("live job status %q after sweep, want %q", got.Status, store.JobAssigned)
	}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		l, err := (store.Leases{}).Current(ctx, c, jobID)
		if err != nil {
			return err
		}
		if l.Epoch != epoch || l.State != store.LeaseGranted {
			t.Errorf("live lease is now epoch %d state %q, want epoch %d state granted",
				l.Epoch, l.State, epoch)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSweeperMarksStaleScanPointsOffline covers the second constant that was
// declared and never compared against anything. Status is what an operator
// reads to decide whether a zone is being scanned at all, so it is the one field
// that must not be able to say "online" about a host that is gone.
func TestSweeperMarksStaleScanPointsOffline(t *testing.T) {
	db := testDB(t)
	tenant, _, spID := enrolledScanPoint(t, db)

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.ScanPoints{}).SetStatus(ctx, c, spID, store.ScanPointOnline); err != nil {
			return err
		}
		_, err := c.Exec(ctx, `
			UPDATE scan_points SET last_heartbeat = now() - interval '10 minutes'
			 WHERE tenant_id = $1 AND scan_point_id = $2`, tenant.UUID(), spID)
		return err
	}); err != nil {
		t.Fatalf("stale the scan point: %v", err)
	}

	newSweeper(t, db).Sweep(context.Background())

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByID(ctx, c, spID)
		if err != nil {
			return err
		}
		if sp.Status != store.ScanPointOffline {
			t.Errorf("scan point status %q after %s without a heartbeat, want offline",
				sp.Status, store.HeartbeatTimeout)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSweeperSeesEveryActiveTenant is the ADR-036 hole earning its keep. The
// sweep has no tenant of its own; if the enumeration missed a tenant, that
// tenant's expired leases would never be swept and the failure would be
// invisible — a job stuck in one customer's estate and a green log everywhere.
func TestSweeperSeesEveryActiveTenant(t *testing.T) {
	db := testDB(t)
	tenantA, _, spA := enrolledScanPoint(t, db)
	tenantB, _, spB := enrolledScanPoint(t, db)
	if tenantA == tenantB {
		t.Fatal("fixture gave both scan points the same tenant; this test proves nothing")
	}

	jobA, _ := leaseFor(t, db, tenantA, spA, true)
	jobB, _ := leaseFor(t, db, tenantB, spB, true)
	backdateLease(t, db, tenantA, jobA, time.Minute)
	backdateLease(t, db, tenantB, jobB, time.Minute)

	newSweeper(t, db).Sweep(context.Background())

	for _, tc := range []struct {
		name   string
		tenant store.TenantID
		job    uuid.UUID
	}{{"A", tenantA, jobA}, {"B", tenantB, jobB}} {
		if got := jobRow(t, db, tc.tenant, tc.job); got.Status != store.JobQueued {
			t.Errorf("tenant %s: job status %q after sweep, want queued — the sweep did not "+
				"reach this tenant", tc.name, got.Status)
		}
	}
}
