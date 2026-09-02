package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// leaseOne claims and leases the job, returning the epoch CancelJob must name.
func leaseOne(t *testing.T, db *store.DB, tenant store.TenantID, spID, jobID uuid.UUID) int64 {
	t.Helper()
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
	return epoch
}

// TestAKilledScanGetsCancelJobToo closes the asymmetry between the two halves of
// stopping a scan.
//
// Jobs.Claim has excluded 'cancelled' AND 'killed' from the outset, while
// CancellableFor matched 'cancelled' only. So a killed scan stopped being handed
// out and its IN-FLIGHT jobs were told nothing — the one state where the scan is
// most demonstrably still touching the estate.
func TestAKilledScanGetsCancelJobToo(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "killed-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE scans SET status = 'killed' WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), pj.ScanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 1 {
			t.Fatalf("cancellable jobs under a KILLED scan = %d, want 1", len(pending))
		}
		if pending[0].JobID != pj.JobID || pending[0].Epoch != epoch {
			t.Errorf("cancellable job = %v epoch %d, want %v epoch %d",
				pending[0].JobID, pending[0].Epoch, pj.JobID, epoch)
		}
		// The reason on the wire and in the audit log says which of the two
		// happened. An operator reading "cancelled" about a scan they killed has
		// been told something untrue about their own action.
		if pending[0].ScanStatus != store.ScanKilled {
			t.Errorf("scan status = %q, want %q", pending[0].ScanStatus, store.ScanKilled)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCancellationIsMeasurable is ADR-024's KillAck argument applied to the
// per-scan half: an unmeasurable cancellation is not a control.
func TestCancellationIsMeasurable(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "cancelack-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	// The operator API is a later session, so this is what it will do: status
	// and the instant the bound is measured from, in one statement.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE scans SET status = 'cancelled', cancel_requested_at = now()
			  WHERE tenant_id = $1 AND scan_id = $2`, c.Tenant().UUID(), pj.ScanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Before the ack: the job is in the set an operator chases.
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.CancelAcks{}).Unacknowledged(ctx, c, pj.ScanID)
		if err != nil {
			return err
		}
		if len(un) != 1 || un[0].JobID != pj.JobID || un[0].ScanPointID != spID {
			t.Fatalf("unacknowledged = %+v, want the one leased job", un)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch, 4); err != nil {
			return err
		}
		// Idempotent. A scan point that reconnects and acks again must not
		// produce a second row, or "how many acknowledged" stops meaning
		// anything.
		return (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch, 4)
	}); err != nil {
		t.Fatalf("record ack: %v", err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.CancelAcks{}).Unacknowledged(ctx, c, pj.ScanID)
		if err != nil {
			return err
		}
		if len(un) != 0 {
			t.Errorf("unacknowledged after the ack = %d, want 0", len(un))
		}

		acks, err := (store.CancelAcks{}).ForScan(ctx, c, pj.ScanID)
		if err != nil {
			return err
		}
		if len(acks) != 1 {
			t.Fatalf("acks = %d, want 1 — the second Record must be a no-op, not a second row", len(acks))
		}
		if acks[0].Epoch != epoch {
			t.Errorf("ack epoch = %d, want %d; an ack under a stale epoch halted work "+
				"Core was no longer asking about", acks[0].Epoch, epoch)
		}
		if acks[0].TasksHalted != 4 {
			t.Errorf("tasks_halted = %d, want 4", acks[0].TasksHalted)
		}
		if acks[0].Latency == nil {
			t.Error("latency is nil although the scan recorded cancel_requested_at; " +
				"a bound Core cannot measure is not a control")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestUnmeasuredCancellationLatencyIsNilRatherThanZero.
//
// Nothing sets scans.cancel_requested_at yet — the operator API is a later
// session. Reporting an unmeasured bound as "0s" would be a gate that silently
// passes, which is the failure this repository treats as worse than one that
// fails outright.
func TestUnmeasuredCancellationLatencyIsNilRatherThanZero(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "unmeasured-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := c.Exec(ctx, `UPDATE scans SET status = 'cancelled' WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), pj.ScanID); err != nil {
			return err
		}
		return (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch, 1)
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		acks, err := (store.CancelAcks{}).ForScan(ctx, c, pj.ScanID)
		if err != nil {
			return err
		}
		if len(acks) != 1 {
			t.Fatalf("acks = %d, want 1", len(acks))
		}
		if acks[0].Latency != nil {
			t.Errorf("latency = %v with no cancel_requested_at, want nil", *acks[0].Latency)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestACancelAckWithoutAnEpochIsRefused. An epoch of zero names no incarnation
// (ADR-012), so there is nothing to record the acknowledgement against.
func TestACancelAckWithoutAnEpochIsRefused(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "noepoch-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)
	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, 0, 1)
	}); err == nil {
		t.Error("an acknowledgement with no lease epoch was accepted")
	}
}

// ============================================================================
// Kill switch scope
// ============================================================================

// TestAKillReachesOnlyTheScanPointsItCovers.
//
// LiveFor was an unscoped read: every live kill in the tenant went to every scan
// point, and the wire message carried only a kill_id. A zone kill therefore
// halted the whole fleet, and the receiver had nothing to filter on — the only
// safe reading of a bare kill_id is "halt everything".
//
// Narrowing at Core rather than on the scan point is the point. A scan point
// sits in a network whose compromise the threat model assumes (ADR-020), and the
// one message it must never be able to talk itself out of is the one that stops
// it.
func TestAKillReachesOnlyTheScanPointsItCovers(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "killscope-"+uuid.NewString()[:8])

	zoneA, spA := seedZonedPoint(t, db, tenant)
	_, spB := seedZonedPoint(t, db, tenant)

	var killID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		k, err := (store.KillSwitches{}).Issue(ctx, c, store.KillZone, &zoneA, nil, nil, "zone halt")
		if err != nil {
			return err
		}
		killID = k.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		inZone, err := (store.KillSwitches{}).LiveFor(ctx, c, spA)
		if err != nil {
			return err
		}
		if len(inZone) != 1 || inZone[0].ID != killID {
			t.Errorf("the scan point IN the killed zone saw %d kills, want the one issued", len(inZone))
		}
		outside, err := (store.KillSwitches{}).LiveFor(ctx, c, spB)
		if err != nil {
			return err
		}
		if len(outside) != 0 {
			t.Errorf("a scan point outside the killed zone saw %d kills, want 0. A zone kill "+
				"delivered fleet-wide is a tenant kill with a misleading name.", len(outside))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// And it stops assignment in that zone, not just in-flight work. Claim
	// handled 'tenant' and 'scan' and not 'zone', so a zone kill halted the
	// zone's running jobs and dispatch handed the same scan points fresh ones
	// two seconds later, forever.
	seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	if n := claimCount(t, db, tenant, spA, nil); n != 0 {
		t.Errorf("claimed %d jobs into a killed zone, want 0", n)
	}
	if n := claimCount(t, db, tenant, spB, nil); n != 1 {
		t.Errorf("claimed %d jobs on a scan point outside the killed zone, want 1 — if this "+
			"is 0 the case above proves nothing", n)
	}
}

// TestAScanScopedKillStopsItsScan.
//
// The wire KillSwitch carries a scope and no job ids, so a scan point receiving
// a scan-scoped kill cannot tell which of the jobs it holds are covered. Marking
// the scan killed is what closes that: Claim already refuses a killed scan's
// queued jobs, and CancellableFor turns its in-flight ones into per-job
// CancelJob messages that name the job and the epoch.
//
// A kill that records itself and does not stop the scan is the failure the whole
// table exists to prevent.
func TestAScanScopedKillStopsItsScan(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "scankill-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)
	_, spOther := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.KillSwitches{}).Issue(ctx, c, store.KillScan, nil, &pj.ScanID, nil, "runaway scan")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var status store.ScanStatus
		if err := c.QueryRow(ctx, `SELECT status FROM scans WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), pj.ScanID).Scan(&status); err != nil {
			return err
		}
		if status != store.ScanKilled {
			t.Errorf("scan status = %q, want %q. A scan-scoped kill that leaves the scan "+
				"running produces a wire message that halts nothing.", status, store.ScanKilled)
		}

		// The in-flight job now has a CancelJob to carry, naming the incarnation.
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 1 || pending[0].JobID != pj.JobID || pending[0].Epoch != epoch {
			t.Errorf("cancellable = %+v, want the leased job at epoch %d", pending, epoch)
		}

		// The kill reaches the scan point holding that scan's work, and not one
		// that holds none of it.
		held, err := (store.KillSwitches{}).LiveFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(held) != 1 {
			t.Errorf("the scan point holding the killed scan's job saw %d kills, want 1", len(held))
		}
		idle, err := (store.KillSwitches{}).LiveFor(ctx, c, spOther)
		if err != nil {
			return err
		}
		if len(idle) != 0 {
			t.Errorf("a scan point holding none of the killed scan's jobs saw %d kills, want 0", len(idle))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// Per-scan safety mode
// ============================================================================

// TestIntrusiveOptInIsRefusedAboveThePolicy is ADR-021's ceiling, at the writer.
//
// The policy sets the ceiling and the scan opts in beneath it. Refusing is an
// error rather than a silent downgrade: a caller that asked for intrusive and
// got safe without being told would report a scan it did not run.
func TestIntrusiveOptInIsRefusedAboveThePolicy(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "optin-"+uuid.NewString()[:8])

	safePolicy := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	intrusivePolicy := seedPolicyJob(t, db, tenant, "intrusive", "[]", "[]")

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		err := (store.Scans{}).SetSafetyMode(ctx, c, safePolicy.ScanID, store.SafetyIntrusive, nil)
		if !errors.Is(err, store.ErrSafetyModeAbovePolicy) {
			t.Errorf("SetSafetyMode(intrusive) under a safe policy = %v, want ErrSafetyModeAbovePolicy", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Scans{}).SetSafetyMode(ctx, c, intrusivePolicy.ScanID, store.SafetyIntrusive, nil); err != nil {
			return err
		}
		var mode store.SafetyMode
		if err := c.QueryRow(ctx, `SELECT safety_mode FROM scans WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), intrusivePolicy.ScanID).Scan(&mode); err != nil {
			return err
		}
		if mode != store.SafetyIntrusive {
			t.Errorf("scans.safety_mode = %q, want intrusive", mode)
		}

		// ADR-021 requires the audit event on selection, and it is written in
		// the same transaction: an opt-in recorded without its event, or an
		// event without the opt-in, is worse than either alone.
		events, err := (store.AuditEvents{}).ListByResource(ctx, c, "scan", intrusivePolicy.ScanID, 10)
		if err != nil {
			return err
		}
		if len(events) != 1 || events[0].Action != "scan.safety_mode_selected" {
			t.Fatalf("audit events = %+v, want one scan.safety_mode_selected", events)
		}
		if events[0].Detail["safety_mode"] != "intrusive" {
			t.Errorf("audit detail safety_mode = %v, want intrusive", events[0].Detail["safety_mode"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestSafetyModeCannotBeChangedOnceTheScanStarts.
//
// Constraints are computed at claim time and never re-pushed, so escalating a
// running scan would apply to its queued jobs and not to the ones already
// dispatched — a half-applied escalation reported as a whole one. Cancellation
// is the lever for a running scan.
func TestSafetyModeCannotBeChangedOnceTheScanStarts(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "started-"+uuid.NewString()[:8])
	pj := seedPolicyJob(t, db, tenant, "intrusive", "[]", "[]")

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE scans SET status = 'running', started_at = now()
		                        WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), pj.ScanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		err := (store.Scans{}).SetSafetyMode(ctx, c, pj.ScanID, store.SafetyIntrusive, nil)
		if !errors.Is(err, store.ErrScanAlreadyStarted) {
			t.Errorf("SetSafetyMode on a running scan = %v, want ErrScanAlreadyStarted", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestForJobCarriesBothHalvesOfTheSafetyDecision. Dispatch cannot compute the
// effective mode from the policy alone, and the read that feeds it has to bring
// both.
func TestForJobCarriesBothHalvesOfTheSafetyDecision(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "forjob-"+uuid.NewString()[:8])
	pj := seedPolicyJob(t, db, tenant, "intrusive", "[]", `[{"start":"22:00","end":"04:00"}]`)

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		p, err := (store.Policies{}).ForJob(ctx, c, pj.JobID)
		if err != nil {
			return err
		}
		if p.SafetyMode != store.SafetyIntrusive {
			t.Errorf("policy safety_mode = %q, want intrusive", p.SafetyMode)
		}
		// Default for every scan, including every one written before the column
		// existed. That default is the control: a policy left on intrusive
		// authorises nothing on its own.
		if p.ScanSafetyMode != store.SafetySafe {
			t.Errorf("scan safety_mode = %q, want safe by default", p.ScanSafetyMode)
		}
		if len(p.TimeWindows) == 0 {
			t.Error("time_windows did not travel; dispatch cannot compute window_ends_unix")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// Regressions from the session 8e review round. Each of these was a real
// bypass, proved against this database before it was fixed.
// ============================================================================

// TestTheAcknowledgementSetIsScopedLikeDelivery.
//
// LiveFor grew a scope predicate and Unacknowledged did not, so a zone kill
// delivered to one scan point reported every other one in the tenant as
// delinquent — forever, for a message Core never sent them. Worse than an absent
// measurement: a scan point that genuinely dropped the kill becomes
// indistinguishable from the ones that were never covered.
func TestTheAcknowledgementSetIsScopedLikeDelivery(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "ackscope-"+uuid.NewString()[:8])

	zoneA, spA := seedZonedPoint(t, db, tenant)
	_, spB := seedZonedPoint(t, db, tenant)

	var killID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		k, err := (store.KillSwitches{}).Issue(ctx, c, store.KillZone, &zoneA, nil, nil, "zone halt")
		if err != nil {
			return err
		}
		killID = k.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.KillSwitches{}).Unacknowledged(ctx, c, killID)
		if err != nil {
			return err
		}
		if len(un) != 1 || un[0] != spA {
			t.Fatalf("unacknowledged = %v, want only the scan point in the killed zone (%v). "+
				"A scan point that was never sent the kill can never clear it, so the set "+
				"never empties and stops being actionable.", un, spA)
		}
		if un[0] == spB {
			t.Error("the scan point outside the killed zone is being chased")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// And it empties once the covered scan point answers.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.KillSwitches{}).Ack(ctx, c, killID, spA, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.KillSwitches{}).Unacknowledged(ctx, c, killID)
		if err != nil {
			return err
		}
		if len(un) != 0 {
			t.Errorf("unacknowledged after the covered scan point acked = %v, want empty", un)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAScanKillSurvivesLeaseExpiry.
//
// Both predicates keyed on scan_jobs.scan_point_id, which ExpireLeases nulls
// when it requeues a job — so a scan point that partitioned while scanning
// stopped matching at the exact moment it became the thing an operator most
// needs to stop. It is still holding a lease and still sending packets; Core had
// simply lost its own record of who to talk to. The previous unscoped Live()
// was accidentally right about this, so narrowing delivery introduced it.
func TestAScanKillSurvivesLeaseExpiry(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "expiredkill-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	// The scan point partitions. Its lease runs out and the sweeper requeues.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		// Both columns: job_leases_expiry_after_grant would refuse an expiry
		// before the grant, which is the constraint doing its job.
		if _, err := c.Exec(ctx,
			`UPDATE job_leases
			    SET granted_at = now() - interval '10 minutes',
			        expires_at = now() - interval '1 minute'
			  WHERE tenant_id = $1 AND job_id = $2`, c.Tenant().UUID(), pj.JobID); err != nil {
			return err
		}
		expired, err := (store.Leases{}).ExpireLeases(ctx, c, 10)
		if err != nil {
			return err
		}
		if len(expired) != 1 {
			t.Fatalf("expired %d leases, want 1 — if this is 0 the test proves nothing", len(expired))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Only now does the operator act.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.KillSwitches{}).Issue(ctx, c, store.KillScan, nil, &pj.ScanID, nil, "runaway")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		kills, err := (store.KillSwitches{}).LiveFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(kills) != 1 {
			t.Errorf("LiveFor = %d kills after the lease expired, want 1. The scan point is "+
				"still holding an unreleased lease and may still be sending packets; the "+
				"kill switch exists because ADR-012's self-abort cannot be relied on.", len(kills))
		}

		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 1 {
			t.Fatalf("CancellableFor = %d after the lease expired, want 1", len(pending))
		}
		if pending[0].Epoch != epoch {
			t.Errorf("CancelJob names epoch %d, want the one this scan point holds (%d). "+
				"Naming the job's highest epoch would address an incarnation it does not have.",
				pending[0].Epoch, epoch)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// And it stops, eventually. StillHoldingGrace bounds the chase: a lease that
	// ExpireLeases moved out of 'granted' can never be marked released — Release
	// and ReleaseAny both require 'granted', so not even the scan point's own
	// JobTerminal can do it — and an unbounded "not released" test would re-send
	// this cancellation on every reconnect for the life of the tenant, which is
	// the same set-never-empties failure from the other side.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE job_leases
			    SET granted_at = now() - interval '2 hours',
			        expires_at = now() - interval '1 hour'
			  WHERE tenant_id = $1 AND job_id = $2`, c.Tenant().UUID(), pj.JobID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		kills, err := (store.KillSwitches{}).LiveFor(ctx, c, spID)
		if err != nil {
			return err
		}
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(kills) != 0 || len(pending) != 0 {
			t.Errorf("an hour past the lease: LiveFor=%d CancellableFor=%d, want 0 and 0. "+
				"A scan point still absent long after its lease ended is an outage an "+
				"operator is already looking at, not a cancellation they are waiting on.",
				len(kills), len(pending))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAReportedTerminalStopsTheCancellation. The normal path: a scan point that
// reports its terminal releases the lease, and is not told again.
func TestAReportedTerminalStopsTheCancellation(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "released-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE scans SET status = 'cancelled' WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), pj.ScanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 1 {
			t.Fatalf("control: cancellable = %d before the terminal, want 1", len(pending))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// What onTerminal does when the scan point reports.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Leases{}).Release(ctx, c, pj.JobID, epoch, spID, store.LeaseReleased)
	}); err != nil {
		t.Fatalf("release: %v", err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		pending, err := (store.Jobs{}).CancellableFor(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(pending) != 0 {
			t.Errorf("cancellable = %d after the scan point reported its terminal, want 0 — "+
				"re-sending would ask it to cancel work it has already reported on", len(pending))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAnUnsolicitedCancelAckIsRefused.
//
// Record validated only epoch > 0, which made the whole measurement forgeable in
// the one direction that matters: a scan point could pre-acknowledge its own
// future cancellation, and when an operator later cancelled the runaway scan the
// job was already absent from the set they chase. Pre-acknowledging is not a
// control, it is a way to disappear from one.
func TestAnUnsolicitedCancelAckIsRefused(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "forgedack-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)
	_, spOther := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	epoch := leaseOne(t, db, tenant, spID, pj.JobID)

	// Before any operator action, the scan point acks anyway.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		err := (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch, 0)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an ack for a scan nobody has cancelled = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE scans SET status = 'cancelled', cancel_requested_at = now()
			  WHERE tenant_id = $1 AND scan_id = $2`, c.Tenant().UUID(), pj.ScanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		// A stale epoch is refused rather than counted. Three comments promised
		// that and nothing read the column.
		if err := (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch+9000, 1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an ack naming an epoch this scan point does not hold = %v, want ErrNotFound", err)
		}
		// A scan point that never held the job cannot write a row for it.
		if err := (store.CancelAcks{}).Record(ctx, c, pj.JobID, spOther, epoch, 1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an ack from a scan point that never held the job = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		un, err := (store.CancelAcks{}).Unacknowledged(ctx, c, pj.ScanID)
		if err != nil {
			return err
		}
		if len(un) != 1 {
			t.Errorf("unacknowledged = %d after three refused acks, want 1. A refused ack "+
				"must leave the job in the set an operator chases.", len(un))
		}
		acks, err := (store.CancelAcks{}).ForScan(ctx, c, pj.ScanID)
		if err != nil {
			return err
		}
		if len(acks) != 0 {
			t.Errorf("cancel_acks holds %d forged rows; cvap_app has no DELETE on that table", len(acks))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The real one is accepted, and an honest retry after a reconnect is not an
	// error — collapsing the retry into the refusal would make the well-behaved
	// scan point indistinguishable from the forged ack.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch, 2); err != nil {
			return err
		}
		return (store.CancelAcks{}).Record(ctx, c, pj.JobID, spID, epoch, 2)
	}); err != nil {
		t.Fatalf("the owed acknowledgement was refused: %v", err)
	}
}

// TestAZoneIdIsMatchedCaseInsensitively.
//
// scan_zones.zone_id::text renders lowercase canonical and jsonb_exists is
// byte-exact, so an allowlist holding an uppercase uuid matched nothing: an
// operator's zone restriction silently became a restriction to no zone at all.
// Fail-closed, so not a hole — but a control that quietly does something other
// than what it says is not one either.
func TestAZoneIdIsMatchedCaseInsensitively(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "zonecase-"+uuid.NewString()[:8])
	zoneA, spA := seedZonedPoint(t, db, tenant)

	seedPolicyJob(t, db, tenant, "safe", `["`+strings.ToUpper(zoneA.String())+`"]`, "[]")
	if n := claimCount(t, db, tenant, spA, nil); n != 1 {
		t.Errorf("claimed %d jobs under an allowlist naming this zone in uppercase, want 1", n)
	}
}

// TestAMalformedZoneEntryIsRefusedAtWriteTime.
//
// Validated by a trigger rather than by a cast inside Jobs.Claim: a ::uuid cast
// in the claim predicate would make one malformed element raise and fail every
// claim in the TENANT rather than just that policy's.
func TestAMalformedZoneEntryIsRefusedAtWriteTime(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "zoneshape-"+uuid.NewString()[:8])

	for _, zones := range []string{`["not-a-uuid"]`, `[123]`, `[null]`, `["", "x"]`} {
		err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
			_, err := c.Exec(ctx,
				`INSERT INTO scan_policies (tenant_id, name, allowed_zones)
				 VALUES ($1,$2,$3::jsonb)`,
				c.Tenant().UUID(), "z-"+uuid.NewString()[:8], zones)
			return err
		})
		if err == nil {
			t.Errorf("allowed_zones %s was accepted; the claim predicate can never match it, "+
				"so the policy silently restricts to no zone at all", zones)
		}
	}
}

// TestTheSafetyModeCeilingIsStructural.
//
// SetSafetyMode was the sole writer only by convention: cvap_app holds
// column-wide UPDATE on scans, so a future scan-creation API could write
// intrusive directly and never pass the ceiling check. A CHECK cannot see
// scan_policies and every writer runs as the same role, so the rule has to be a
// trigger to be a rule — the same argument migration 0020's ingest_state ratchet
// makes.
func TestTheSafetyModeCeilingIsStructural(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "ceiling-"+uuid.NewString()[:8])
	safePolicy := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE scans SET safety_mode = 'intrusive'
		                        WHERE tenant_id = $1 AND scan_id = $2`,
			c.Tenant().UUID(), safePolicy.ScanID)
		return err
	}); err == nil {
		t.Error("a direct UPDATE raised a scan above its policy's ceiling, bypassing " +
			"SetSafetyMode and ADR-021's audit event")
	}

	// And on INSERT, which is the path a scan-creation API would take.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type, safety_mode)
			 VALUES ($1,$2,'discovery','intrusive')`,
			c.Tenant().UUID(), safePolicy.PolicyID)
		return err
	}); err == nil {
		t.Error("a scan was CREATED intrusive under a safe policy")
	}

	// The permitted direction still works.
	intrusive := seedPolicyJob(t, db, tenant, "intrusive", "[]", "[]")
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Scans{}).SetSafetyMode(ctx, c, intrusive.ScanID, store.SafetyIntrusive, nil)
	}); err != nil {
		t.Errorf("the ceiling refused an opt-in its policy permits: %v", err)
	}
}
