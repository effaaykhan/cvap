package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Enrollment token and scan point certificate persistence.
//
// Persistence only. The token's plaintext never appears in this package: the
// service hashes it and passes the hash, so a bearer credential is never
// something this layer holds, logs, or could accidentally return.

// EnrollmentToken is a stored token record. It carries the hash, never the
// token — see the comment on enrollment_tokens.token_hash in migration 0017.
type EnrollmentToken struct {
	ID          uuid.UUID
	ZoneID      uuid.UUID
	IssuedBy    *uuid.UUID
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RedeemedAt  *time.Time
	Description string
}

// RedeemedToken is what a successful redemption yields: the zone the operator
// chose, and the token's id for the audit record.
type RedeemedToken struct {
	TokenID uuid.UUID
	ZoneID  uuid.UUID
}

type EnrollmentTokens struct{}

// Issue records a new token. tokenHash is SHA-256 of the token; the caller keeps
// the plaintext and hands it to the operator exactly once.
func (EnrollmentTokens) Issue(ctx context.Context, c *Conn, tokenHash []byte, zoneID uuid.UUID, issuedBy *uuid.UUID, expiresAt time.Time, description string) (*EnrollmentToken, error) {
	const q = `
		INSERT INTO enrollment_tokens
		    (tenant_id, zone_id, token_hash, issued_by, expires_at, description)
		VALUES ($1, $2, $3, $4, $5, nullif($6, ''))
		RETURNING token_id, zone_id, issued_by, issued_at, expires_at,
		          redeemed_at, coalesce(description, '')`

	var t EnrollmentToken
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), zoneID, tokenHash, issuedBy, expiresAt, description).
		Scan(&t.ID, &t.ZoneID, &t.IssuedBy, &t.IssuedAt, &t.ExpiresAt, &t.RedeemedAt, &t.Description)
	if err != nil {
		return nil, mapError(err)
	}
	return &t, nil
}

// PendingZone reads the zone a token was issued for, WITHOUT redeeming it.
//
// ADVISORY, and the naming is deliberate. This is not the single-use gate and
// must never be treated as one: two callers can both read the same pending
// token here and both proceed. It exists only because the scan point row has to
// exist before Redeem can name it — enrollment_tokens.redeemed_scan_point is a
// composite FK to scan_points — so something has to supply the zone first.
//
// The authoritative check is Redeem, which runs last and rolls the whole
// transaction back if it matches nothing. A loser here still loses there.
func (EnrollmentTokens) PendingZone(ctx context.Context, c *Conn, tokenHash []byte) (uuid.UUID, error) {
	const q = `
		SELECT zone_id
		  FROM enrollment_tokens
		 WHERE tenant_id = $1
		   AND token_hash = $2
		   AND redeemed_at IS NULL
		   AND expires_at > clock_timestamp()`

	var zoneID uuid.UUID
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), tokenHash).Scan(&zoneID); err != nil {
		return uuid.Nil, mapError(err)
	}
	return zoneID, nil
}

// Redeem marks a token used, atomically, and returns what it authorised.
//
// ============================================================================
// This single UPDATE is what makes a token single-use. Read before changing it.
// ============================================================================
//
// A token redeemed twice is two scan points holding one identity — two peers
// that authenticate as the same fleet member, in an audit log that cannot tell
// them apart. So the check and the write must not be separable.
//
// They are not, because this is ONE conditional UPDATE. Under READ COMMITTED a
// second transaction reaching the same row BLOCKS on the row lock, and when the
// first commits it does not simply proceed: it re-evaluates its WHERE clause
// against the updated row (EvalPlanQual). It sees redeemed_at IS NOT NULL,
// matches nothing, and reports zero rows affected. Exactly one caller can ever
// see RowsAffected() == 1.
//
// A SELECT followed by an UPDATE would NOT be safe — the two interleave, and
// both callers see an unredeemed token. Neither would a check in Go. The
// atomicity is a property of UPDATE re-checking its own predicate after a lock
// wait; it is not something this code arranges, and it is not something a
// refactor can preserve by accident.
//
// clock_timestamp(), not now(). now() is transaction_timestamp(): it returns
// when the TRANSACTION began, so after a lock wait the predicate is re-evaluated
// against a stale reading and a token revoked or expired during the wait is
// still redeemable. The window is the length of the enrolling transaction —
// small, and not zero. clock_timestamp() reads the wall clock at evaluation,
// which is what makes "the database clock decides" actually true.
//
// It is in the predicate rather than checked in Go so that an app server with a
// skewed clock cannot extend a token's life.
//
// The caller MUST run this inside the same transaction as the scan point
// insert, so that a later failure — a signing error, a constraint violation —
// rolls the redemption back and does not burn the token.
//
// It also runs AFTER that insert, which looks like the wrong order and is not:
// redeemed_scan_point is a composite FK to scan_points, so the row must exist
// before this statement can name it. Redeeming first fails on the foreign key.
// Running last costs nothing, because everything is one transaction — a token
// this call refuses takes the scan point down with it.
func (EnrollmentTokens) Redeem(ctx context.Context, c *Conn, tokenHash []byte, scanPointID uuid.UUID) (*RedeemedToken, error) {
	const q = `
		UPDATE enrollment_tokens
		   SET redeemed_at = now(), redeemed_scan_point = $3
		 WHERE tenant_id = $1
		   AND token_hash = $2
		   AND redeemed_at IS NULL
		   AND expires_at > clock_timestamp()
		RETURNING token_id, zone_id`

	var r RedeemedToken
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), tokenHash, scanPointID).
		Scan(&r.TokenID, &r.ZoneID)
	if err != nil {
		// ErrNotFound here covers unknown, expired, already redeemed, and lost
		// the race. Deliberately indistinguishable: the caller must not be able
		// to probe which, and it has nothing useful to do differently anyway.
		return nil, mapError(err)
	}
	return &r, nil
}

// Revoke cancels an unredeemed token by expiring it.
//
// Expiry rather than deletion: the row is what proves a token was issued and by
// whom, and an operator revoking one should leave a record rather than remove
// the evidence. It is also not "redeemed by nobody" — a revoked token was never
// used, and marking it redeemed would put a lie in the audit trail.
func (EnrollmentTokens) Revoke(ctx context.Context, c *Conn, tokenID uuid.UUID) error {
	const q = `
		UPDATE enrollment_tokens
		   SET expires_at = least(expires_at, clock_timestamp())
		 WHERE tenant_id = $1 AND token_id = $2 AND redeemed_at IS NULL`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), tokenID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPending is the operator's view of unredeemed tokens. It returns hashes'
// metadata, never anything from which a token could be reconstructed.
func (EnrollmentTokens) ListPending(ctx context.Context, c *Conn, limit int) ([]EnrollmentToken, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	const q = `
		SELECT token_id, zone_id, issued_by, issued_at, expires_at,
		       redeemed_at, coalesce(description, '')
		  FROM enrollment_tokens
		 WHERE tenant_id = $1 AND redeemed_at IS NULL AND expires_at > now()
		 ORDER BY expires_at
		 LIMIT $2`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.ZoneID, &t.IssuedBy, &t.IssuedAt, &t.ExpiresAt,
			&t.RedeemedAt, &t.Description); err != nil {
			return nil, mapError(err)
		}
		out = append(out, t)
	}
	return out, mapError(rows.Err())
}
