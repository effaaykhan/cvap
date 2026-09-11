package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// A scan settles when its last job ends — completed if any job completed,
// failed if every job failed — and is left alone while work is in flight.
// Nothing did this before, so scans read "running" forever (S42).
func TestScanSettlesWhenItsJobsEnd(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "settle")
	ctx := context.Background()

	var scanID, j1, j2 uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		var policyID uuid.UUID
		if err := c.QueryRow(ctx, `INSERT INTO scan_policies (tenant_id, name) VALUES ($1,'settle') RETURNING policy_id`, tid).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `INSERT INTO scans (tenant_id, policy_id, scan_type, status) VALUES ($1,$2,'discovery','running') RETURNING scan_id`, tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe, status) VALUES ($1,$2,'discovery',true,'completed') RETURNING job_id`, tid, scanID).Scan(&j1); err != nil {
			return err
		}
		return c.QueryRow(ctx, `INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe, status) VALUES ($1,$2,'discovery',true,'running') RETURNING job_id`, tid, scanID).Scan(&j2)
	}); err != nil {
		t.Fatal(err)
	}

	status := func() string {
		var st string
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx, `SELECT status::text FROM scans WHERE tenant_id = $1 AND scan_id = $2`, c.Tenant().UUID(), scanID).Scan(&st)
		}); err != nil {
			t.Fatal(err)
		}
		return st
	}

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		got, err := (store.Scans{}).SettleIfDone(ctx, c, scanID)
		if err != nil {
			return err
		}
		if got != "" {
			t.Errorf("settled to %q with a job still running", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if status() != "running" {
		t.Fatalf("scan left running: status = %q", status())
	}

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := c.Exec(ctx, `UPDATE scan_jobs SET status = 'failed' WHERE tenant_id = $1 AND job_id = $2`, c.Tenant().UUID(), j2); err != nil {
			return err
		}
		got, err := (store.Scans{}).SettleIfDone(ctx, c, scanID)
		if err != nil {
			return err
		}
		if got != store.ScanCompleted {
			t.Errorf("settled to %q, want completed (one job completed, one failed)", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if status() != "completed" {
		t.Errorf("status = %q after the last job ended, want completed", status())
	}
	_ = j1
}
