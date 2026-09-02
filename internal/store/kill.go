package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// KillScope mirrors the kill_scope enum.
type KillScope string

const (
	KillTenant KillScope = "tenant"
	KillZone   KillScope = "zone"
	KillScan   KillScope = "scan"
)

// KillSwitch is one operator kill action (ADR-024).
type KillSwitch struct {
	ID         uuid.UUID
	Scope      KillScope
	ZoneID     *uuid.UUID
	ScanID     *uuid.UUID
	IssuedBy   *uuid.UUID
	IssuedAt   time.Time
	Reason     string
	ResolvedAt *time.Time
}

type KillSwitches struct{}

// Issue records a kill. Propagation is dispatch's job; this is the record the
// acknowledgements are measured against.
func (KillSwitches) Issue(ctx context.Context, c *Conn, scope KillScope, zoneID, scanID, issuedBy *uuid.UUID, reason string) (*KillSwitch, error) {
	const q = `
		INSERT INTO kill_switches (tenant_id, scope, scope_zone_id, scope_scan_id, issued_by, reason)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING kill_id, scope, scope_zone_id, scope_scan_id, issued_by,
		          issued_at, reason, resolved_at`

	var k KillSwitch
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), string(scope), zoneID, scanID, issuedBy, reason).
		Scan(&k.ID, &k.Scope, &k.ZoneID, &k.ScanID, &k.IssuedBy, &k.IssuedAt, &k.Reason, &k.ResolvedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &k, nil
}

// Ack records one scan point acknowledging one kill.
//
// Idempotent: a scan point that reconnects and acks again must not produce a
// second row, or "how many acknowledged" stops meaning anything. The primary key
// enforces that; ON CONFLICT DO NOTHING makes the retry a no-op rather than an
// error the scan point would keep retrying.
func (KillSwitches) Ack(ctx context.Context, c *Conn, killID, scanPointID uuid.UUID, tasksHalted int) error {
	const q = `
		INSERT INTO kill_acks (tenant_id, kill_id, scan_point_id, tasks_halted)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, kill_id, scan_point_id) DO NOTHING`

	_, err := c.Exec(ctx, q, c.Tenant().UUID(), killID, scanPointID, tasksHalted)
	return mapError(err)
}

// Live returns kills still expecting acknowledgements.
func (KillSwitches) Live(ctx context.Context, c *Conn) ([]KillSwitch, error) {
	const q = `
		SELECT kill_id, scope, scope_zone_id, scope_scan_id, issued_by,
		       issued_at, reason, resolved_at
		  FROM kill_switches
		 WHERE tenant_id = $1 AND resolved_at IS NULL
		 ORDER BY issued_at DESC`

	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []KillSwitch
	for rows.Next() {
		var k KillSwitch
		if err := rows.Scan(&k.ID, &k.Scope, &k.ZoneID, &k.ScanID, &k.IssuedBy,
			&k.IssuedAt, &k.Reason, &k.ResolvedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, k)
	}
	return out, mapError(rows.Err())
}

// Unacknowledged is the query ADR-024's 10-second bound is measured with.
//
// "A 10-second bound Core cannot measure is not a control." This returns the
// scan points that were online when the kill was issued and have not
// acknowledged it — which is the set an operator acts on during an incident,
// and the reason kill_acks is a table rather than a line in the audit log.
func (KillSwitches) Unacknowledged(ctx context.Context, c *Conn, killID uuid.UUID) ([]uuid.UUID, error) {
	const q = `
		SELECT sp.scan_point_id
		  FROM scan_points sp
		 WHERE sp.tenant_id = $1
		   AND sp.status IN ('online', 'pending')
		   AND NOT EXISTS (
		       SELECT 1 FROM kill_acks a
		        WHERE a.tenant_id = $1 AND a.kill_id = $2
		          AND a.scan_point_id = sp.scan_point_id
		   )
		 ORDER BY sp.scan_point_id`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), killID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, mapError(err)
		}
		out = append(out, id)
	}
	return out, mapError(rows.Err())
}
