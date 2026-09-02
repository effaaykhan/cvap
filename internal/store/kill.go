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

// StillHoldingGrace is how long after a lease ends a scan point is still told to
// stop.
//
// 'released' alone is not enough, and the reason is a sharp edge in the lease
// API: Release and ReleaseAny both require state = 'granted', so once
// ExpireLeases has moved a lease to 'expired' or 'lost' NOTHING can mark it
// released — not even the scan point's own JobTerminal. A criterion of "not
// released" would therefore chase such a job forever, re-sending CancelJob on
// every reconnect and holding the job in the unacknowledged set for the life of
// the tenant. That is the "never empties, stops being actionable" failure again,
// reached from the other side.
//
// Fifteen minutes against a 60-second lease TTL: long enough that a scan point
// which partitioned, had its lease expired and then came back is still told to
// stop, short enough that the set drains. A scan point still absent after
// fifteen minutes is an outage an operator is already looking at, not a
// cancellation they are waiting on.
//
// A SQL interval rather than a parameter because it is interpolated into two
// query constants with different placeholder numbering; it is a compile-time
// constant from this file and never touches anything a caller supplies.
const StillHoldingGrace = `interval '15 minutes'`

type KillSwitches struct{}

// Issue records a kill. Propagation is dispatch's job; this is the record the
// acknowledgements are measured against.
//
// A SCAN-scoped kill also marks its scan killed, in the same transaction.
//
// ============================================================================
// Why that is one action and not two.
// ============================================================================
//
// The wire KillSwitch carries a scope and no job ids, so a scan point receiving
// a scan-scoped kill cannot tell which of the jobs it holds are covered: it
// knows job ids, and nothing on the assignment tells it which scan a job belongs
// to. Halting everything would make a narrow kill as blunt as a tenant-wide one,
// which is the whole reason the scope field exists.
//
// scans.status = 'killed' is what closes that. Jobs.Claim already refuses to
// hand out a killed scan's queued jobs, and Jobs.CancellableFor turns its
// in-flight ones into per-job CancelJob messages that name the job and the
// epoch. So the kill switch says "stop this scan" once and the two existing
// mechanisms do the narrowing, rather than a second scope-aware halt path on the
// scan point.
//
// Written here rather than left to the caller because a kill that records itself
// and does not stop the scan is the failure mode this whole table exists to
// prevent — and a two-call sequence is one an operator API can perform half of.
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

	if scope == KillScan && scanID != nil {
		// Terminal states are left alone: a completed scan does not become
		// killed because someone aimed a kill at it afterwards, and rewriting
		// its status would lose how it actually ended. Matching no row is not an
		// error — the kill is still recorded, which is the point.
		// cancel_requested_at as well as the status, in the same statement.
		// Migration 0025 states that requirement for whatever stops a scan, and
		// this is the first writer that does: without it CancelAcks.ForScan
		// reports nil latency for every killed scan, and since the 'cancelled'
		// path has no production writer yet, the only stopped-scan path that
		// exists would be the one whose ADR-024 bound cannot be measured.
		const markKilled = `
			UPDATE scans
			   SET status = 'killed',
			       completed_at = now(),
			       cancel_requested_at = coalesce(cancel_requested_at, now())
			 WHERE tenant_id = $1 AND scan_id = $2
			   AND status IN ('pending', 'planning', 'running')`
		if _, err := c.Exec(ctx, markKilled, c.Tenant().UUID(), *scanID); err != nil {
			return nil, mapError(err)
		}
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
// Without this nothing ever writes resolved_at, so LiveFor returns every kill
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

// killCoversScanPoint is the ONE definition of which scan points a kill covers.
//
// ============================================================================
// Delivery and the acknowledgement set must be the same set.
// ============================================================================
//
// They were not. LiveFor grew a scope predicate and Unacknowledged kept asking
// about every scan point in the tenant, so a zone kill delivered to one scan
// point reported every other one as delinquent — forever, for a message Core
// never sent them. That is precisely the "the set never empties and stops being
// actionable" failure Unacknowledged's own comment gives as its reason for
// excluding scan points that were never reachable, reintroduced one function
// along. One const, interpolated nowhere, so the two cannot drift again.
//
// The scan arm keys on the LEASE rather than on scan_jobs.scan_point_id, and
// that is the substantive part. ExpireLeases sets scan_point_id = NULL and
// requeues a reassign_safe job, or fails a job that is not — so a scan point
// that partitioned while scanning stops matching a scan_point_id test at the
// exact moment it becomes the thing an operator most needs to stop. It is still
// holding an unreleased lease, and it is still sending packets.
//
// Over-delivering a kill is the correct error direction. Under-delivering one is
// how the unscoped Live() this replaced was accidentally right.
//
// Both queries below bind the scan point as `sp`, so this text is identical in
// each.
const killCoversScanPoint = `
		   AND (
		        -- NOT IN rather than = 'tenant', so a kill_scope value a later
		        -- migration adds is delivered to EVERYONE until someone teaches
		        -- this predicate about it. It matches killScope()'s documented
		        -- fail-safe in dispatch, which maps an unknown scope to
		        -- UNSPECIFIED = halt everything. Matching only 'tenant' here
		        -- made that default branch unreachable, and a new scope would
		        -- have reached nobody.
		        k.scope NOT IN ('zone', 'scan')
		        OR (k.scope = 'zone' AND k.scope_zone_id = sp.zone_id)
		        OR (k.scope = 'scan' AND EXISTS (
		            SELECT 1
		              FROM scan_jobs j
		              JOIN job_leases l
		                ON l.tenant_id = j.tenant_id AND l.job_id = j.job_id
		             WHERE j.tenant_id = k.tenant_id
		               AND j.scan_id = k.scope_scan_id
		               AND l.holder_scan_point = sp.scan_point_id
		               AND l.state <> 'released'
		               AND l.expires_at > now() - ` + StillHoldingGrace + `
		        ))
		   )`

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

// LiveFor returns the live kills that COVER one scan point.
//
// ============================================================================
// Core narrows delivery. The scan point does not decide whether a kill is its.
// ============================================================================
//
// This was an unscoped read: every live kill in the tenant went to every scan
// point, and the wire message carried only a kill_id. A zone kill therefore
// halted the whole tenant's fleet, and there was no way for it not to — the
// receiver had nothing to filter on and the only safe reading of a bare kill_id
// is "halt everything".
//
// Narrowing here rather than on the scan point is not an optimisation. A scan
// point cannot be trusted to decide that a kill does not apply to it: it sits in
// a network whose compromise the threat model assumes (ADR-020), and the one
// message it must never be able to talk itself out of is the one that stops it.
// So Core sends a kill only to the scan points it covers, and
// KillSwitch.scope then says how much of what that scan point holds to halt.
//
// A scan-scoped kill reaches a scan point that holds an unreleased lease on one
// of that scan's jobs — see killCoversScanPoint for why the LEASE and not
// scan_jobs.scan_point_id. It halts nothing on its own: Issue marks the scan
// killed and the jobs arrive individually as CancelJob. It still travels, so an
// operator watching one scan point can see why its work is being cancelled.
func (KillSwitches) LiveFor(ctx context.Context, c *Conn, scanPointID uuid.UUID) ([]KillSwitch, error) {
	const q = `
		SELECT k.kill_id, k.scope, k.scope_zone_id, k.scope_scan_id, k.issued_by,
		       k.issued_at, k.reason, k.resolved_at
		  FROM kill_switches k
		  JOIN scan_points sp
		    ON sp.tenant_id = k.tenant_id AND sp.scan_point_id = $2
		 WHERE k.tenant_id = $1
		   AND k.resolved_at IS NULL` + killCoversScanPoint + `
		 ORDER BY k.issued_at DESC`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanPointID)
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
// Scope-aware, and it has to be. LiveFor narrows delivery; a set that did not
// narrow with it names scan points that were never sent the message they are
// being chased for, and which can therefore never clear it. That is the same
// "never empties, stops being actionable" failure the paragraph above gives as
// the reason 'pending' scan points are excluded — and it is worse than an absent
// measurement, because a scan point that genuinely dropped the kill becomes
// indistinguishable from the dozens that were never covered.
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
		   )` + killCoversScanPoint + `
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
