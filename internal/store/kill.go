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

// Resolve stops a kill expecting acknowledgements.
//
// Without this nothing ever writes resolved_at, so Live() returns every kill
// ever issued, forever: a kill from months ago is replayed to every scan point
// on every reconnect, and Jobs.Claim refuses to assign anything for the life of
// the tenant. A control with no off switch is an outage with extra steps.
func (KillSwitches) Resolve(ctx context.Context, c *Conn, killID uuid.UUID) error {
	const q = `
		UPDATE kill_switches SET resolved_at = now()
		 WHERE tenant_id = $1 AND kill_id = $2 AND resolved_at IS NULL`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), killID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AckLatency is how long a kill took to reach each scan point that answered.
//
// ADR-024's standard is "a 10-second bound Core cannot measure is not a
// control", and a SET of unacknowledged scan points does not measure a bound —
// it says who is missing, not whether the ones who answered were fast enough.
// issued_at and acked_at were both already recorded; nothing computed the
// difference. This does.
type AckLatency struct {
	ScanPointID uuid.UUID
	Latency     time.Duration
}

func (KillSwitches) AckLatency(ctx context.Context, c *Conn, killID uuid.UUID) ([]AckLatency, error) {
	const q = `
		SELECT a.scan_point_id,
		       extract(epoch FROM (a.acked_at - k.issued_at)) * 1000
		  FROM kill_acks a
		  JOIN kill_switches k
		    ON k.tenant_id = a.tenant_id AND k.kill_id = a.kill_id
		 WHERE a.tenant_id = $1 AND a.kill_id = $2
		 ORDER BY 2 DESC`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), killID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []AckLatency
	for rows.Next() {
		var l AckLatency
		var ms float64
		if err := rows.Scan(&l.ScanPointID, &ms); err != nil {
			return nil, mapError(err)
		}
		l.Latency = time.Duration(ms) * time.Millisecond
		out = append(out, l)
	}
	return out, mapError(rows.Err())
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

// Unacknowledged is the set an operator chases during an incident.
//
// The set is scan points that were plausibly REACHABLE when the kill was
// issued — a heartbeat within the 90s timeout as of that moment — and have not
// acknowledged. Not `status = 'online'`: status is current, and markOffline
// writes it on disconnect, so a scan point that was online at issue and dropped
// a second later would silently leave the set and make the bound look met when
// nothing was delivered. last_heartbeat is a fact about a past instant and does
// not move under the query.
//
// 'pending' is excluded for the opposite reason: a scan point enrolled but never
// connected was never reachable, and leaving it in means the set never empties
// and stops being actionable.
//
// This is the WHO. AckLatency is the HOW LONG, and ADR-024's bound needs both.
func (KillSwitches) Unacknowledged(ctx context.Context, c *Conn, killID uuid.UUID) ([]uuid.UUID, error) {
	const q = `
		SELECT sp.scan_point_id
		  FROM scan_points sp
		  JOIN kill_switches k
		    ON k.tenant_id = sp.tenant_id AND k.kill_id = $2
		 WHERE sp.tenant_id = $1
		   AND sp.last_heartbeat IS NOT NULL
		   AND sp.last_heartbeat > k.issued_at - interval '90 seconds'
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
