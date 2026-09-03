package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Persistence only, like the rest of this package. Whether a password is
// correct, whether a session may be issued, and what a role's permissions
// authorise are decisions for internal/control/api; this file stores and
// retrieves the facts those decisions are made from.

// AuthMethod mirrors the auth_method enum.
type AuthMethod string

const (
	AuthOIDC  AuthMethod = "oidc"
	AuthLocal AuthMethod = "local"
)

// ErrSessionInvalid is the single outcome for every way a session token fails:
// unknown, expired, revoked, or belonging to a user who has since been disabled.
//
// One sentinel, deliberately. A caller that could tell "expired" from "unknown"
// would be an oracle for which tokens have ever existed, and the operator-facing
// answer is the same in every case: sign in again.
var ErrSessionInvalid = errors.New("store: session is not valid")

// ErrCredentialLocked means the account is inside its lockout window.
//
// Distinguished from a wrong password INSIDE this package because the caller
// needs to know whether to count another failure. The API must not distinguish
// them to the client — see the handler, where both become one response.
var ErrCredentialLocked = errors.New("store: credential is locked")

// AuthConfig is a tenant's authentication configuration.
//
// There is no client secret field, and its absence is the decision recorded in
// migration 0026: the OIDC client is public and uses authorization code + PKCE,
// because a confidential client means a per-tenant secret in a table that a
// backup, a read replica or one injection yields.
type AuthConfig struct {
	Method            AuthMethod
	OIDCIssuer        string
	OIDCClientID      string
	OIDCEmailClaim    string
	OIDCAutoProvision bool
	OIDCDefaultRoleID *uuid.UUID
	UpdatedAt         time.Time
}

type AuthConfigs struct{}

// Get returns the tenant's auth configuration.
//
// ErrNotFound means the tenant has none, which is not a default to fill in: a
// deployment that has not decided how its users authenticate must fail to log
// anyone in rather than fall back to something.
func (AuthConfigs) Get(ctx context.Context, c *Conn) (*AuthConfig, error) {
	const q = `
		SELECT method, coalesce(oidc_issuer, ''), coalesce(oidc_client_id, ''),
		       oidc_email_claim, oidc_auto_provision, oidc_default_role_id, updated_at
		  FROM tenant_auth_config
		 WHERE tenant_id = $1`

	var a AuthConfig
	err := c.QueryRow(ctx, q, c.Tenant().UUID()).Scan(
		&a.Method, &a.OIDCIssuer, &a.OIDCClientID, &a.OIDCEmailClaim,
		&a.OIDCAutoProvision, &a.OIDCDefaultRoleID, &a.UpdatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &a, nil
}

// Upsert writes the tenant's auth configuration.
//
// Setting Method to local does NOT enable local authentication. Core refuses it
// unless the deployment-wide flag is set and the tenant is on-prem, and that
// check lives in the API rather than here precisely because it is not a property
// of the row: a tenant admin who could turn on password login for their own
// users would have opted their tenant out of the deployment operator's SSO
// policy, which is the reason the flag is Core-wide.
func (AuthConfigs) Upsert(ctx context.Context, c *Conn, a AuthConfig, actor *uuid.UUID) error {
	switch a.Method {
	case AuthOIDC, AuthLocal:
	default:
		return fmt.Errorf("store: unknown auth method %q", a.Method)
	}
	if a.OIDCEmailClaim == "" {
		a.OIDCEmailClaim = "email"
	}

	const q = `
		INSERT INTO tenant_auth_config
			(tenant_id, method, oidc_issuer, oidc_client_id, oidc_email_claim,
			 oidc_auto_provision, oidc_default_role_id, updated_at, updated_by)
		VALUES ($1, $2::text::auth_method, nullif($3, ''), nullif($4, ''), $5, $6, $7, now(), $8)
		ON CONFLICT (tenant_id) DO UPDATE SET
			method               = excluded.method,
			oidc_issuer          = excluded.oidc_issuer,
			oidc_client_id       = excluded.oidc_client_id,
			oidc_email_claim     = excluded.oidc_email_claim,
			oidc_auto_provision  = excluded.oidc_auto_provision,
			oidc_default_role_id = excluded.oidc_default_role_id,
			updated_at           = now(),
			updated_by           = excluded.updated_by`

	if _, err := c.Exec(ctx, q, c.Tenant().UUID(), string(a.Method), a.OIDCIssuer,
		a.OIDCClientID, a.OIDCEmailClaim, a.OIDCAutoProvision, a.OIDCDefaultRoleID, actor); err != nil {
		return mapError(err)
	}
	return nil
}

// Session is a row of sessions, joined to what authorisation needs.
//
// Permissions come from the ROLE at lookup time rather than being copied into
// the session at login. A permission set frozen at login means a revoked role
// keeps working until the session expires, which for a 12-hour cap is most of a
// working day after an operator believed they had removed access.
type Session struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	RoleID      uuid.UUID
	Email       string
	Permissions []byte // jsonb, from roles
	CSRFHash    []byte
	IssuedAt    time.Time
	ExpiresAt   time.Time
	MustChange  bool
}

type Sessions struct{}

// Create issues a session.
//
// Takes HASHES, never the tokens, for the same reason ResolveEnrollmentTokenTenant
// does: the token is a bearer credential and this package must not be a place
// one is handled. Hashing happens next to the type that carries the plaintext.
func (Sessions) Create(ctx context.Context, c *Conn, userID uuid.UUID, tokenHash, csrfHash []byte, ttl time.Duration, ip *string, userAgent string) (uuid.UUID, error) {
	if len(tokenHash) == 0 || len(csrfHash) == 0 {
		return uuid.Nil, errors.New("store: session requires both token and csrf hashes")
	}

	const q = `
		INSERT INTO sessions
			(tenant_id, user_id, token_hash, csrf_hash, expires_at, created_ip, user_agent)
		VALUES ($1, $2, $3, $4, now() + $5::interval, $6::text::inet, $7)
		RETURNING session_id`

	var id uuid.UUID
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), userID, tokenHash, csrfHash,
		fmt.Sprintf("%d seconds", int64(ttl.Seconds())), ip, userAgent).Scan(&id)
	if err != nil {
		return uuid.Nil, mapError(err)
	}
	return id, nil
}

// Lookup resolves a session token hash to the session and its authorisation.
//
// The validity predicate is in SQL, not in the caller, for the reason ADR-041
// gives about the pre-tenant functions: a filter the caller applies is a filter
// a caller can forget, and this one decides whether a request is authenticated.
//
// It joins users and roles because all three are needed on every request and a
// disabled user must stop working immediately — not when their session expires.
func (Sessions) Lookup(ctx context.Context, c *Conn, tokenHash []byte) (*Session, error) {
	if len(tokenHash) == 0 {
		return nil, ErrSessionInvalid
	}

	const q = `
		SELECT s.session_id, s.user_id, u.role_id, u.email, r.permissions,
		       s.csrf_hash, s.issued_at, s.expires_at,
		       coalesce(cr.must_change, false)
		  FROM sessions s
		  JOIN users u ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id
		  JOIN roles r ON r.tenant_id = u.tenant_id AND r.role_id = u.role_id
		  LEFT JOIN user_credentials cr
		         ON cr.tenant_id = s.tenant_id AND cr.user_id = s.user_id
		 WHERE s.tenant_id = $1
		   AND s.token_hash = $2
		   AND s.revoked_at IS NULL
		   AND s.expires_at > now()
		   AND u.status = 'active'`

	var s Session
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), tokenHash).Scan(
		&s.ID, &s.UserID, &s.RoleID, &s.Email, &s.Permissions,
		&s.CSRFHash, &s.IssuedAt, &s.ExpiresAt, &s.MustChange)
	if err != nil {
		if errors.Is(mapError(err), ErrNotFound) {
			return nil, ErrSessionInvalid
		}
		return nil, mapError(err)
	}
	return &s, nil
}

// Touch records activity. It does NOT extend expiry.
//
// The distinction is the whole point: last_seen_at is for the operator looking
// at their active sessions, and sessions.expires_at is capped at 12 hours from
// issue by a CHECK constraint. A sliding expiry that renews on activity is a
// session that never ends for an active attacker.
func (Sessions) Touch(ctx context.Context, c *Conn, id uuid.UUID) error {
	const q = `UPDATE sessions SET last_seen_at = now() WHERE tenant_id = $1 AND session_id = $2`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), id)
	return mapError(err)
}

// Revoke ends one session. Idempotent: revoking an already-revoked session is
// not an error, because the caller's intent is satisfied either way.
func (Sessions) Revoke(ctx context.Context, c *Conn, id uuid.UUID, reason string) error {
	const q = `
		UPDATE sessions SET revoked_at = now(), revoked_reason = $3
		 WHERE tenant_id = $1 AND session_id = $2 AND revoked_at IS NULL`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), id, reason)
	return mapError(err)
}

// RevokeAllForUser ends every live session a user holds.
//
// Called on password change and on administrative disablement. Both are moments
// where the answer to "is this session still the person who signed in" changed,
// and leaving other sessions alive would mean a stolen session survives the
// password change made because it was stolen.
func (Sessions) RevokeAllForUser(ctx context.Context, c *Conn, userID uuid.UUID, reason string) error {
	const q = `
		UPDATE sessions SET revoked_at = now(), revoked_reason = $3
		 WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), userID, reason)
	return mapError(err)
}

// Credential is a local password verifier and its lockout state.
type Credential struct {
	UserID         uuid.UUID
	PasswordHash   string
	MustChange     bool
	FailedAttempts int
	LockedUntil    *time.Time
}

type Credentials struct{}

// Get returns the credential for a user, or ErrCredentialLocked if the account
// is inside its lockout window.
//
// The lock is reported rather than folded into "wrong password" because the
// caller must not count another failure against a locked account — that would
// let a stream of wrong guesses extend the lockout indefinitely, which is a
// denial of service against the real user delivered by the control meant to
// protect them.
func (Credentials) Get(ctx context.Context, c *Conn, userID uuid.UUID) (*Credential, error) {
	const q = `
		SELECT user_id, password_hash, must_change, failed_attempts, locked_until
		  FROM user_credentials
		 WHERE tenant_id = $1 AND user_id = $2`

	var cr Credential
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), userID).Scan(
		&cr.UserID, &cr.PasswordHash, &cr.MustChange, &cr.FailedAttempts, &cr.LockedUntil)
	if err != nil {
		return nil, mapError(err)
	}
	if cr.LockedUntil != nil && cr.LockedUntil.After(time.Now()) {
		return nil, fmt.Errorf("%w until %s", ErrCredentialLocked, cr.LockedUntil.UTC().Format(time.RFC3339))
	}
	return &cr, nil
}

// LockoutThreshold and LockoutWindow are the local-auth lockout.
//
// Modest numbers, because local auth exists for on-prem deployments where the
// alternative is no authentication at all, and because a lockout is the wrong
// tool for a determined attacker anyway — argon2id is what makes guessing
// expensive. This stops the opportunistic case and bounds the damage.
const (
	LockoutThreshold = 10
	LockoutWindow    = 15 * time.Minute
)

// RecordFailure counts a wrong password and locks the account at the threshold.
//
// The count and the lock are one statement so that concurrent attempts cannot
// interleave a read and a write and lose failures between them.
func (Credentials) RecordFailure(ctx context.Context, c *Conn, userID uuid.UUID) error {
	const q = `
		UPDATE user_credentials
		   SET failed_attempts = failed_attempts + 1,
		       locked_until = CASE WHEN failed_attempts + 1 >= $3
		                           THEN now() + $4::interval ELSE locked_until END
		 WHERE tenant_id = $1 AND user_id = $2`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), userID, LockoutThreshold,
		fmt.Sprintf("%d seconds", int64(LockoutWindow.Seconds())))
	return mapError(err)
}

// RecordSuccess clears the failure count and any lock.
func (Credentials) RecordSuccess(ctx context.Context, c *Conn, userID uuid.UUID) error {
	const q = `
		UPDATE user_credentials SET failed_attempts = 0, locked_until = NULL
		 WHERE tenant_id = $1 AND user_id = $2 AND (failed_attempts <> 0 OR locked_until IS NOT NULL)`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), userID)
	return mapError(err)
}

// Set writes a password verifier.
//
// Takes the ENCODED PHC string, never a password: hashing belongs next to the
// type that carries the plaintext, and a store that accepted a password would be
// a store that could log one.
func (Credentials) Set(ctx context.Context, c *Conn, userID uuid.UUID, phc string, mustChange bool) error {
	const q = `
		INSERT INTO user_credentials (tenant_id, user_id, password_hash, must_change, updated_at)
		VALUES ($1, $2, $3, $4, now())
		-- The TENANT-SCOPED unique constraint, not the bare primary key.
		--
		-- user_id is a server-generated uuid, so there is no attacker-controlled
		-- collision here today. The conflict target is the composite one anyway,
		-- because this is the pattern that gets copied — and copied onto a table
		-- with a CLIENT-chosen key it becomes migration 0022's bug, where one
		-- tenant's submission id collided with another's.
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET
			password_hash   = excluded.password_hash,
			must_change     = excluded.must_change,
			updated_at      = now(),
			failed_attempts = 0,
			locked_until    = NULL`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), userID, phc, mustChange)
	return mapError(err)
}
