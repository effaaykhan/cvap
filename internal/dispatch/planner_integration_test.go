package dispatch_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/dispatch"
	"github.com/effaaykhan/cvap/internal/store"
)

// planFixture is a tenant with a policy, so a scan can be created.
func planFixture(t *testing.T) (*store.DB, store.TenantID, uuid.UUID) {
	t.Helper()
	db := testDB(t)
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var policyID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "plan-"+uuid.NewString()[:8],
			"plan"+strings.ReplaceAll(uuid.NewString(), "-", "")[:20]+".test", store.DeploymentOnPrem); err != nil {
			return err
		}
		p, err := (store.Policies{}).Create(ctx, c, store.PolicySpec{Name: "p", SafetyMode: store.SafetySafe})
		if err != nil {
			return err
		}
		policyID = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return db, tenant, policyID
}

func createScan(t *testing.T, db *store.DB, tenant store.TenantID, policyID uuid.UUID, scanType string, targets []store.ScanTarget) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		s, err := (store.Scans{}).Create(ctx, c, policyID, scanType, nil, targets)
		if err != nil {
			return err
		}
		id = s.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func scanStatus(t *testing.T, db *store.DB, tenant store.TenantID, scanID uuid.UUID) store.ScanStatus {
	t.Helper()
	var s *store.Scan
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		s, err = (store.Scans{}).Get(ctx, c, scanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s.Status
}

func taskTargets(t *testing.T, db *store.DB, tenant store.TenantID, scanID uuid.UUID) []string {
	t.Helper()
	var out []string
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		rows, err := c.Query(ctx, `
			SELECT t.task_target FROM scan_tasks t
			  JOIN scan_jobs j ON j.tenant_id = t.tenant_id AND j.job_id = t.job_id
			 WHERE t.tenant_id = $1 AND j.scan_id = $2
			 ORDER BY t.task_target`, tenant.UUID(), scanID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func planOnce(t *testing.T, db *store.DB, tenant store.TenantID) {
	t.Helper()
	dispatch.PlanPending(context.Background(), db,
		slog.New(slog.NewJSONHandler(io.Discard, nil)), tenant, 20)
}

// TestPlanningWritesCanonicalTargets, end to end through the store.
//
// The scan declares its targets in five spellings of two hosts plus a /30. What
// reaches scan_tasks.task_target is one canonical string per host — which is
// what makes ADR-024's per-target ceilings countable, and what the scan point's
// re-computation will agree with.
func TestPlanningWritesCanonicalTargets(t *testing.T) {
	db, tenant, policyID := planFixture(t)
	scanID := createScan(t, db, tenant, policyID, "discovery", []store.ScanTarget{
		{Type: "host", Value: "192.0.2.5:443", Authorized: true},
		{Type: "host", Value: "[192.0.2.5]", Authorized: true},
		{Type: "url", Value: "https://SCANNER.corp.example/status", Authorized: true},
		{Type: "cidr", Value: "198.51.100.0/30", Authorized: true},
	})

	planOnce(t, db, tenant)

	if got := scanStatus(t, db, tenant, scanID); got != store.ScanRunning {
		t.Fatalf("status after planning = %q, want running", got)
	}

	got := taskTargets(t, db, tenant, scanID)
	want := []string{
		"192.0.2.5", "192.0.2.5", // two spellings, one canonical form each
		"198.51.100.0", "198.51.100.1", "198.51.100.2", "198.51.100.3",
		"scanner.corp.example",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("task targets = %v\nwant %v", got, want)
	}
}

// TestAnUnauthorisedTargetFailsTheWholeScan.
//
// Execution-plan §8 risk 6. Not skipped, not planned partially: a scan that
// quietly omitted a target would report coverage of a network nobody agreed to,
// and the operator would have no signal that it happened.
func TestAnUnauthorisedTargetFailsTheWholeScan(t *testing.T) {
	db, tenant, policyID := planFixture(t)
	scanID := createScan(t, db, tenant, policyID, "discovery", []store.ScanTarget{
		{Type: "host", Value: "192.0.2.5", Authorized: true},
		{Type: "host", Value: "192.0.2.6", Authorized: false},
	})

	planOnce(t, db, tenant)

	if got := scanStatus(t, db, tenant, scanID); got != store.ScanFailed {
		t.Errorf("status = %q, want failed", got)
	}
	if got := taskTargets(t, db, tenant, scanID); len(got) != 0 {
		t.Errorf("an unauthorised target produced %d planned tasks; the scan must plan nothing", len(got))
	}
}

// TestATargetWithNoCanonicalFormFailsTheScan — ADR-040 at planning, where an
// operator can be told rather than at claim time where they cannot.
func TestATargetWithNoCanonicalFormFailsTheScan(t *testing.T) {
	db, tenant, policyID := planFixture(t)
	scanID := createScan(t, db, tenant, policyID, "discovery", []store.ScanTarget{
		{Type: "host", Value: "192.000.2.5", Authorized: true},
	})

	planOnce(t, db, tenant)

	if got := scanStatus(t, db, tenant, scanID); got != store.ScanFailed {
		t.Errorf("status = %q, want failed", got)
	}

	var reason string
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT detail->>'reason' FROM audit_events
			  WHERE tenant_id = $1 AND action = 'scan.planning_failed' AND resource_id = $2`,
			tenant.UUID(), scanID).Scan(&reason)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "192.000.2.5") {
		t.Errorf("the audit event's reason does not name the offending target: %q", reason)
	}
}

// TestAnUnknownScanTypeFailsTheScan.
//
// scans.scan_type is free text because engines are extensible; engineFor is Core
// saying what it can actually plan. An unrecognised type must fail the scan
// rather than queue a job for an engine kind no scan point declares, which would
// sit unclaimed forever and present as a dispatch problem.
func TestAnUnknownScanTypeFailsTheScan(t *testing.T) {
	db, tenant, policyID := planFixture(t)
	scanID := createScan(t, db, tenant, policyID, "quantum-audit", []store.ScanTarget{
		{Type: "host", Value: "192.0.2.5", Authorized: true},
	})

	planOnce(t, db, tenant)

	if got := scanStatus(t, db, tenant, scanID); got != store.ScanFailed {
		t.Errorf("status = %q, want failed", got)
	}
}

// TestAPlannedScanIsNotPlannedTwice.
//
// The sweeper runs every ten seconds and PlanPending selects on status =
// 'pending'; the status moves inside the same transaction that writes the tasks,
// so a second pass finds nothing. Without that, every tick would plan the scan
// again and a ten-second sweep would be a duplicate scan every ten seconds.
func TestAPlannedScanIsNotPlannedTwice(t *testing.T) {
	db, tenant, policyID := planFixture(t)
	scanID := createScan(t, db, tenant, policyID, "discovery", []store.ScanTarget{
		{Type: "host", Value: "192.0.2.5", Authorized: true},
	})

	planOnce(t, db, tenant)
	first := taskTargets(t, db, tenant, scanID)
	planOnce(t, db, tenant)
	second := taskTargets(t, db, tenant, scanID)

	if len(first) != 1 || len(second) != len(first) {
		t.Errorf("planning twice produced %d then %d tasks; a scan must be planned once",
			len(first), len(second))
	}
}

// TestACancelledScanIsNeverPlanned.
//
// The status guard is in the UPDATE's predicate rather than a read-then-write,
// so an operator cancelling between the sweeper's list and its plan wins the
// race. The alternative is a scan whose operator stopped it and which then
// queued jobs anyway.
func TestACancelledScanIsNeverPlanned(t *testing.T) {
	db, tenant, policyID := planFixture(t)
	scanID := createScan(t, db, tenant, policyID, "discovery", []store.ScanTarget{
		{Type: "host", Value: "192.0.2.5", Authorized: true},
	})
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Scans{}).Cancel(ctx, c, scanID, nil, "operator changed their mind")
	}); err != nil {
		t.Fatal(err)
	}

	planOnce(t, db, tenant)

	if got := scanStatus(t, db, tenant, scanID); got != store.ScanCancelled {
		t.Errorf("status = %q, want cancelled", got)
	}
	if got := taskTargets(t, db, tenant, scanID); len(got) != 0 {
		t.Errorf("a cancelled scan was planned into %d tasks", len(got))
	}
}
