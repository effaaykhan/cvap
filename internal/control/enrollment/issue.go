package enrollment

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// Issuer mints enrollment tokens for operators.
//
// Separate from Service because it is not part of the scan point protocol: a
// token is created through the operator API, by a human with a tenant context
// already established. Nothing a scan point can call reaches this.
type Issuer struct {
	db  *store.DB
	now Clock
}

func NewIssuer(db *store.DB) *Issuer {
	return &Issuer{db: db, now: time.Now}
}

// IssuedToken is what an operator gets back. Exactly once.
type IssuedToken struct {
	// Token is the only copy. The database holds a SHA-256 hash, so this cannot
	// be re-derived, re-sent, or recovered from a backup: an operator who loses
	// it issues a new one.
	//
	// PlaintextToken closes every rendering path, so putting this struct in a
	// log line yields [REDACTED] rather than a fleet credential.
	Token PlaintextToken

	TokenID   uuid.UUID
	ZoneID    uuid.UUID
	ExpiresAt time.Time
}

// Issue creates a single-use, TTL-bounded token for one zone.
//
// The zone is chosen HERE, by an operator, and travels with the token. A scan
// point never asserts it — EnrollRequest has no zone field, because exposure is
// derived from the vantage point an observation was made from (ADR-008) and a
// scan point that could choose its own zone could rewrite the derived exposure
// of every asset it reports.
//
// Pass ttl <= 0 for DefaultTTL. MaxTTL is enforced here and again as a CHECK
// constraint in migration 0017.
func (i *Issuer) Issue(ctx context.Context, tenant store.TenantID, zoneID uuid.UUID, issuedBy *uuid.UUID, ttl time.Duration, description string) (*IssuedToken, error) {
	expiresAt, err := ExpiryFor(i.now(), ttl)
	if err != nil {
		return nil, err
	}

	token, err := NewToken()
	if err != nil {
		return nil, err
	}

	var out IssuedToken
	err = i.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// The zone must belong to this tenant. The composite FK on
		// enrollment_tokens would refuse a foreign zone anyway (ADR-017), but
		// failing here gives the operator a message rather than a constraint
		// name, and proves the zone exists before a token is minted for it.
		if _, err := (store.Zones{}).GetByID(ctx, c, zoneID); err != nil {
			return fmt.Errorf("zone: %w", err)
		}

		rec, err := (store.EnrollmentTokens{}).Issue(ctx, c, token.Hash(), zoneID, issuedBy, expiresAt, description)
		if err != nil {
			return err
		}

		// The audit record names the token by id, never by value. An audit log
		// is widely readable by design; a token written into one is a secret
		// published rather than recorded.
		if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID:      issuedBy,
			ActorType:    store.ActorUser,
			Action:       "enrollment_token.issue",
			ResourceType: "enrollment_token",
			ResourceID:   &rec.ID,
			Detail: map[string]any{
				"zone_id":    zoneID.String(),
				"expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339),
			},
		}); err != nil {
			return err
		}

		out = IssuedToken{Token: token, TokenID: rec.ID, ZoneID: rec.ZoneID, ExpiresAt: rec.ExpiresAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke cancels an unredeemed token.
//
// Implemented as expiry rather than deletion: the row is what proves a token was
// issued and by whom, and an operator revoking one should leave a record, not
// remove the evidence. Marking it redeemed by nobody would break the CHECK that
// pairs redeemed_at with redeemed_scan_point, which is the constraint doing its
// job — a revoked token is not a redeemed one.
func (i *Issuer) Revoke(ctx context.Context, tenant store.TenantID, tokenID uuid.UUID, revokedBy *uuid.UUID) error {
	return i.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.EnrollmentTokens{}).Revoke(ctx, c, tokenID); err != nil {
			return err
		}

		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID:      revokedBy,
			ActorType:    store.ActorUser,
			Action:       "enrollment_token.revoke",
			ResourceType: "enrollment_token",
			ResourceID:   &tokenID,
		})
	})
}
