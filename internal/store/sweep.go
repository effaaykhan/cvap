package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ActiveTenantIDs lists the tenants a background sweep should visit (ADR-036).
//
// ============================================================================
// The second deliberate hole, and the only enumeration in this package.
// ============================================================================
//
// Everything else here takes a TenantID and works inside it. A sweep cannot: the
// thing it reacts to is a scan point that stopped talking, so there is no
// request, no session and no tenant to inherit. RLS on `tenants` means a
// cvap_app connection sees only the tenant it is already scoped to, which is
// correct and is exactly why this cannot be written as an ordinary Read.
//
// It exists because ExpireLeases had no caller. ADR-012 says a non-reassign_safe
// job that loses its lease FAILS rather than silently re-running against a
// customer's estate; without a periodic caller that was a property written down
// and never enforced. A security review found it.
//
// The narrowness is in the database, not here. active_tenant_ids() is
// SECURITY DEFINER, STABLE, parameterless, and returns SETOF uuid — ids and
// nothing else, so it cannot be widened into a cross-tenant read primitive
// without changing the function, the migration and ADR-036 together.
//
// Core-side only. Nothing reachable from a wire handler may call this: a scan
// point's request already resolves to exactly one tenant through the ADR-033
// class, and a handler that needed the whole list would be a handler acting
// outside the tenant that authenticated it.
func (db *DB) ActiveTenantIDs(ctx context.Context) ([]TenantID, error) {
	rows, err := db.pool.Query(ctx, `SELECT active_tenant_ids()`)
	if err != nil {
		return nil, fmt.Errorf("store: enumerate active tenants: %w", err)
	}
	defer rows.Close()

	var out []TenantID
	for rows.Next() {
		var u uuid.UUID
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("store: enumerate active tenants: %w", err)
		}
		t, err := NewTenantID(u)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: enumerate active tenants: %w", err)
	}
	return out, nil
}

// MarkStaleOffline flags scan points that have stopped heartbeating.
//
// The heartbeat timeout was a constant with no enforcement: HeartbeatTimeout was
// declared, documented as "Core times out at 90s", and never compared against
// anything. A scan point that vanished stayed 'online' in the operator's view
// indefinitely — which is the one state that must not be able to lie, because it
// is what an operator reads to decide whether a zone is being scanned at all.
//
// Only 'online' rows move. A scan point that was never online, or is already
// offline, or is suspended, is left alone: this reports liveness and must not
// become a second path that resurrects or overrides an administrative status.
//
// cutoff is passed in rather than computed here so the sweeper owns the clock
// and a test can move it.
func (ScanPoints) MarkStaleOffline(ctx context.Context, c *Conn, cutoff time.Time) ([]uuid.UUID, error) {
	const q = `
		UPDATE scan_points
		   SET status = 'offline'
		 WHERE tenant_id = $1
		   AND status = 'online'
		   AND (last_heartbeat IS NULL OR last_heartbeat < $2)
		RETURNING scan_point_id`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), cutoff)
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
