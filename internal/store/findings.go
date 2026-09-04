package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Findings: the observed instances (ADR-009). Written by Core from observations,
// never by a scan point (ADR-006).

// Finding is one row, as the pipeline writes it.
type Finding struct {
	AssetID    uuid.UUID
	RuleID     uuid.UUID
	DedupKey   string
	Locator    string
	Severity   string
	Confidence float64
	Summary    string
}

// FindingEvidence is what a human verifies the finding by, copied from the
// observation (ADR-016): it must outlive the observation partition.
type FindingEvidence struct {
	ObservationID uuid.UUID
	Type          string // evidence_type enum
	Data          map[string]any
	CapturedAt    time.Time
}

// Exposure is one vantage point that saw the issue (ADR-008). The same finding
// carries several; each is a finding_exposure row.
type Exposure struct {
	ZoneID uuid.UUID
}

type Findings struct{}

// Upsert writes a finding by its dedup key, refreshing it if it already exists.
//
// ============================================================================
// Keyed on dedup_key, so a finding persists across scans — its age, its triage
// state, its history all survive a re-scan (ADR-010).
// ============================================================================
//
// A finding already `remediated` or `closed` that fires again REOPENS to `open`:
// the issue an operator marked fixed is back, and that is a state transition
// worth a history row, which the caller writes. `false_positive` and
// `accepted_risk` are NOT reopened — those are an operator's judgement that the
// finding does not matter, and re-detecting the same true fact should not
// undo it every scan.
//
// Returns the finding id and whether the status was reopened, so the caller can
// record the transition.
func (Findings) Upsert(ctx context.Context, c *Conn, f Finding, seenAt time.Time) (id uuid.UUID, reopened bool, err error) {
	// The reopen signal needs the status BEFORE the upsert, which RETURNING
	// cannot show cleanly, so read the prior row first — in the same
	// transaction, so nothing changes it between the read and the write.
	var priorStatus string
	existed := true
	{
		const sel = `SELECT status FROM findings WHERE tenant_id = $1 AND dedup_key = $2`
		row := c.QueryRow(ctx, sel, c.Tenant().UUID(), f.DedupKey)
		if e := row.Scan(&priorStatus); e != nil {
			existed = false
		}
	}

	const ins = `
		INSERT INTO findings (
		    tenant_id, asset_id, rule_id, source, dedup_key, instance_locator,
		    severity, confidence, status, first_seen, last_seen)
		VALUES ($1, $2, $3, 'network', $4, nullif($5,''), $6, $7, 'open', $8, $8)
		ON CONFLICT (tenant_id, dedup_key) DO UPDATE SET
		    severity   = excluded.severity,
		    confidence = excluded.confidence,
		    last_seen  = excluded.last_seen,
		    status = CASE
		        WHEN findings.status IN ('remediated', 'closed') THEN 'open'
		        ELSE findings.status
		    END
		RETURNING finding_id`

	if e := c.QueryRow(ctx, ins, c.Tenant().UUID(), f.AssetID, f.RuleID, f.DedupKey,
		f.Locator, f.Severity, f.Confidence, seenAt).Scan(&id); e != nil {
		return uuid.Nil, false, mapError(e)
	}

	reopened = existed && (priorStatus == "remediated" || priorStatus == "closed")
	return id, reopened, nil
}

// SetExposure replaces the finding's exposure set with the zones passed.
//
// Replace rather than merge, because the exposure set is a statement about THIS
// scan: a management port that used to be reachable from the DMZ and now is not
// should lose that exposure, and a merge would keep it forever. A finding with
// no exposures is possible in principle and is not written — every finding this
// engine raises came from an observation that had a zone.
func (Findings) SetExposure(ctx context.Context, c *Conn, findingID uuid.UUID, zones []uuid.UUID, at time.Time) error {
	const del = `DELETE FROM finding_exposure WHERE tenant_id = $1 AND finding_id = $2`
	if _, err := c.Exec(ctx, del, c.Tenant().UUID(), findingID); err != nil {
		return mapError(err)
	}
	const ins = `
		INSERT INTO finding_exposure (tenant_id, finding_id, zone_id, last_confirmed)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, finding_id, zone_id) DO UPDATE SET last_confirmed = excluded.last_confirmed`
	for _, z := range zones {
		if _, err := c.Exec(ctx, ins, c.Tenant().UUID(), findingID, z, at); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// ReplaceEvidence sets the finding's evidence to exactly what was passed.
//
// Replace, because evidence describes the current instance: the certificate that
// is expired NOW, not the one that was expired last month. The observation id is
// a soft reference with no FK — the observation partition drops on the 90-day
// clock (ADR-016) — which is why data is COPIED here rather than joined.
func (Findings) ReplaceEvidence(ctx context.Context, c *Conn, findingID uuid.UUID, ev []FindingEvidence) error {
	const del = `DELETE FROM evidence WHERE tenant_id = $1 AND finding_id = $2`
	if _, err := c.Exec(ctx, del, c.Tenant().UUID(), findingID); err != nil {
		return mapError(err)
	}
	const ins = `
		INSERT INTO evidence (tenant_id, finding_id, observation_id, evidence_type, data, captured_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	for _, e := range ev {
		data, err := json.Marshal(e.Data)
		if err != nil {
			return mapError(err)
		}
		var obs any
		if e.ObservationID != uuid.Nil {
			obs = e.ObservationID
		}
		if _, err := c.Exec(ctx, ins, c.Tenant().UUID(), findingID, obs, e.Type, data, e.CapturedAt); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// RecordTransition writes a finding_history row.
//
// A transition log the application can rewrite is not a log (migration 0011:
// no DELETE grant on finding_history), so this only ever inserts. changed_by is
// nil for a transition the engine made rather than an operator.
func (Findings) RecordTransition(ctx context.Context, c *Conn, findingID uuid.UUID, from, to, reason string, at time.Time) error {
	const q = `
		INSERT INTO finding_history (tenant_id, finding_id, from_status, to_status, reason, changed_at)
		VALUES ($1, $2, nullif($3,'')::finding_status, $4::finding_status, $5, $6)`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), findingID, from, to, reason, at)
	return mapError(err)
}

// OpenForAssetLocators returns the open findings on an asset whose endpoint is
// in the given locator set, for the lifecycle: a finding on a re-observed
// endpoint that did not fire this pass has been remediated.
func (Findings) OpenForAssetLocators(ctx context.Context, c *Conn, assetID uuid.UUID, locators []string) ([]OpenFinding, error) {
	if len(locators) == 0 {
		return nil, nil
	}
	const q = `
		SELECT finding_id, dedup_key, coalesce(instance_locator,''), status
		  FROM findings
		 WHERE tenant_id = $1 AND asset_id = $2
		   AND status IN ('open', 'confirmed')
		   AND instance_locator = ANY($3)`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), assetID, locators)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []OpenFinding
	for rows.Next() {
		var f OpenFinding
		if err := rows.Scan(&f.ID, &f.DedupKey, &f.Locator, &f.Status); err != nil {
			return nil, mapError(err)
		}
		out = append(out, f)
	}
	return out, mapError(rows.Err())
}

// OpenFinding is the lifecycle's view of an existing finding.
type OpenFinding struct {
	ID       uuid.UUID
	DedupKey string
	Locator  string
	Status   string
}

// MarkRemediated moves a finding to remediated. Used by the lifecycle when the
// endpoint was re-observed and the rule did not fire — the issue is gone, and
// that is different from the endpoint simply not being scanned.
func (Findings) MarkRemediated(ctx context.Context, c *Conn, findingID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE findings
		   SET status = 'remediated', resolved_at = $3, last_seen = $3
		 WHERE tenant_id = $1 AND finding_id = $2 AND status IN ('open', 'confirmed')`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), findingID, at)
	return mapError(err)
}
