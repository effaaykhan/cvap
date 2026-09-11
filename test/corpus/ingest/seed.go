package main

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// Seeding the minimum an observation needs to hang from: a tenant, a zone per
// zone TYPE, a scan point, a job with a task, and an accepted submission. Mirrors
// the correlate integration tests' scaffold — duplicated rather than exported
// because a test helper exported for one binary is API nobody asked for.

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func freshTenant(ctx context.Context, db *store.DB, label string) (store.TenantID, error) {
	id, err := store.NewTenantID(uuid.New())
	if err != nil {
		return store.TenantID{}, err
	}
	err = db.Write(ctx, id, func(ctx context.Context, c *store.Conn) error {
		domain := "t" + strings.ReplaceAll(id.String(), "-", "")[:20] + ".corpus"
		_, e := (store.Tenants{}).Create(ctx, c, label, domain, store.DeploymentSaaS)
		return e
	})
	return id, err
}

// seedScaffold creates one zone per zone TYPE the plan references (internal,
// external), plus a scan point, job, task and submission. Returns the ids the
// observation inserts need and a zone-type -> zone-id map.
//
// The zone TYPE is what the exposure rule reads (ADR-008), so a zone is created
// with exactly the type its key names — the corpus's segment-b is external, and
// that is what makes the management-port finding fire from it and not from the
// internal segment.
func seedScaffold(ctx context.Context, db *store.DB, tenant store.TenantID, byZone map[string][]obsIn) (spID uuid.UUID, subID string, taskID uuid.UUID, zoneIDs map[string]uuid.UUID, err error) {
	zoneIDs = map[string]uuid.UUID{}
	subID = "corpus-" + uuid.NewString()
	err = db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var firstZone uuid.UUID
		for zt := range byZone {
			z, e := (store.Zones{}).Create(ctx, c, "z-"+zt+"-"+uuid.NewString()[:8], store.ZoneType(zt), 1, "")
			if e != nil {
				return e
			}
			zoneIDs[zt] = z.ID
			if firstZone == uuid.Nil {
				firstZone = z.ID
			}
		}
		sp, e := (store.ScanPoints{}).Create(ctx, c, firstZone, "corpus-sp", "1", "v1", "fp-"+uuid.NewString())
		if e != nil {
			return e
		}
		spID = sp.ID
		jobID, tID, e := seedJobAndTask(ctx, c, sp.ID)
		if e != nil {
			return e
		}
		taskID = tID
		_, e = (store.Submissions{}).Begin(ctx, c, subID, jobID, 1, store.SubmitAccepted, false, "")
		return e
	})
	return spID, subID, taskID, zoneIDs, err
}

func seedJobAndTask(ctx context.Context, c *store.Conn, scanPointID uuid.UUID) (jobID, taskID uuid.UUID, err error) {
	tenant := c.Tenant().UUID()
	suffix := uuid.NewString()[:8]
	var policyID uuid.UUID
	if err = c.QueryRow(ctx,
		`INSERT INTO scan_policies (tenant_id, name) VALUES ($1, $2) RETURNING policy_id`,
		tenant, "corpus-policy-"+suffix).Scan(&policyID); err != nil {
		return
	}
	var scanID uuid.UUID
	if err = c.QueryRow(ctx,
		`INSERT INTO scans (tenant_id, policy_id, scan_type, status) VALUES ($1, $2, 'discovery', 'running')
		 RETURNING scan_id`, tenant, policyID).Scan(&scanID); err != nil {
		return
	}
	if err = c.QueryRow(ctx,
		`INSERT INTO scan_jobs (tenant_id, scan_id, scan_point_id, engine)
		 VALUES ($1, $2, $3, 'fingerprint') RETURNING job_id`,
		tenant, scanID, scanPointID).Scan(&jobID); err != nil {
		return
	}
	err = c.QueryRow(ctx,
		`INSERT INTO scan_tasks (tenant_id, job_id, task_target)
		 VALUES ($1, $2, '10.10.0.1') RETURNING task_id`,
		tenant, jobID).Scan(&taskID)
	return
}
