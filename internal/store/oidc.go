package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrAuthRequestInvalid is the single outcome for every way a callback's state
// fails: unknown, expired, already consumed, or belonging to another tenant.
//
// One sentinel, for the reason ErrSessionInvalid is one: a caller that could
// tell them apart is an oracle for which login attempts exist, and the operator
// answer is the same in every case — start again.
var ErrAuthRequestInvalid = errors.New("store: oidc auth request is not valid")

// OIDCAuthRequest is the server-side state of one in-flight login.
type OIDCAuthRequest struct {
	ID           uuid.UUID
	NonceHash    []byte
	CodeVerifier string
	RedirectURI  string
	ReturnPath   string
	CreatedAt    time.Time
}

type OIDCAuthRequests struct{}

// MaxAuthRequestTTL matches the CHECK constraint in migration 0027.
//
// Enforced here as well, so a caller asking for an hour is refused in Go with a
// message about login attempts rather than by the database with one about a
// constraint name.
const MaxAuthRequestTTL = 10 * time.Minute

// Create records a login attempt.
//
// Takes HASHES of the state and nonce and the PLAINTEXT verifier, and the
// asymmetry is not an oversight: state and nonce are only ever compared, so a
// hash suffices and is what should be at rest. The verifier has to be sent to
// the token endpoint, so it cannot be hashed — migration 0027 records that
// exposure and its bound.
func (OIDCAuthRequests) Create(ctx context.Context, c *Conn, stateHash, nonceHash []byte, codeVerifier, redirectURI, returnPath string, ttl time.Duration) (uuid.UUID, error) {
	switch {
	case len(stateHash) == 0 || len(nonceHash) == 0:
		return uuid.Nil, errors.New("store: an oidc auth request needs state and nonce hashes")
	case codeVerifier == "" || redirectURI == "":
		return uuid.Nil, errors.New("store: an oidc auth request needs a verifier and a redirect_uri")
	case ttl <= 0 || ttl > MaxAuthRequestTTL:
		return uuid.Nil, fmt.Errorf("store: an oidc auth request lives at most %s", MaxAuthRequestTTL)
	}
	if returnPath == "" {
		returnPath = "/"
	}

	const q = `
		INSERT INTO oidc_auth_requests
			(tenant_id, state_hash, nonce_hash, code_verifier, redirect_uri, return_path, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval)
		RETURNING request_id`

	var id uuid.UUID
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), stateHash, nonceHash, codeVerifier,
		redirectURI, returnPath, fmt.Sprintf("%d seconds", int64(ttl.Seconds()))).Scan(&id)
	if err != nil {
		return uuid.Nil, mapError(err)
	}
	return id, nil
}

// Consume redeems a login attempt exactly once.
//
// ============================================================================
// A DELETE with RETURNING, not a read followed by a delete.
// ============================================================================
//
// Single-use is what stops a captured state being replayed, and it is won here
// or not at all: two callbacks arriving with one state race, and the database
// re-evaluating the predicate after a lock wait is what makes exactly one of
// them find a row. A SELECT-then-DELETE lets both read it first.
//
// The expiry is in the predicate for the same reason the validity filters in
// ADR-041's functions are in SQL: a filter the caller applies is a filter a
// caller can forget, and this one decides whether a login is honoured.
//
// The tenant scope is what binds a state to the tenant that minted it. This runs
// inside a transaction opened for the tenant the request HOST resolved to, so a
// state from another tenant is a row RLS does not show — the callback has no way
// to name a tenant and therefore no way to reach one.
func (OIDCAuthRequests) Consume(ctx context.Context, c *Conn, stateHash []byte) (*OIDCAuthRequest, error) {
	if len(stateHash) == 0 {
		return nil, ErrAuthRequestInvalid
	}

	const q = `
		DELETE FROM oidc_auth_requests
		 WHERE tenant_id = $1 AND state_hash = $2 AND expires_at > now()
		RETURNING request_id, nonce_hash, code_verifier, redirect_uri, return_path, created_at`

	var r OIDCAuthRequest
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), stateHash).Scan(
		&r.ID, &r.NonceHash, &r.CodeVerifier, &r.RedirectURI, &r.ReturnPath, &r.CreatedAt)
	if err != nil {
		if errors.Is(mapError(err), ErrNotFound) {
			return nil, ErrAuthRequestInvalid
		}
		return nil, mapError(err)
	}
	return &r, nil
}

// PurgeExpiredAuthRequests removes abandoned login attempts.
//
// An abandoned attempt is the normal case, not an error: somebody clicks sign in
// and closes the tab. Consume already refuses an expired row, so this is
// housekeeping rather than a control — which is why it takes a limit and is
// called from the sweeper rather than from a login path.
func (OIDCAuthRequests) PurgeExpiredAuthRequests(ctx context.Context, c *Conn, limit int) (int, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	const q = `
		DELETE FROM oidc_auth_requests
		 WHERE tenant_id = $1 AND request_id IN (
			SELECT request_id FROM oidc_auth_requests
			 WHERE tenant_id = $1 AND expires_at <= now()
			 LIMIT $2)`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), limit)
	if err != nil {
		return 0, mapError(err)
	}
	return int(tag.RowsAffected()), nil
}

// GetBySubject finds the user an OIDC subject already belongs to.
//
// The subject, not the email, is the identity of a returning user — see the
// column comment in migration 0027. Returns ErrNotFound when no user is linked
// yet, which is the first-login case rather than a failure.
func (Users) GetBySubject(ctx context.Context, c *Conn, subject string) (*User, error) {
	if subject == "" {
		return nil, ErrNotFound
	}
	const q = `
		SELECT user_id, role_id, email, auth_provider, status, created_at
		  FROM users WHERE tenant_id = $1 AND oidc_subject = $2`

	var u User
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), subject).
		Scan(&u.ID, &u.RoleID, &u.Email, &u.Provider, &u.Status, &u.Created)
	if err != nil {
		return nil, mapError(err)
	}
	return &u, nil
}

// LinkSubject binds an OIDC subject to a user that does not have one.
//
// ============================================================================
// Conditional on oidc_subject IS NULL, and that is the whole control.
// ============================================================================
//
// This is the one moment an email is allowed to identify a person, so it is the
// one moment an identity provider that let somebody claim an unverified address
// could hand them an account here. Two things bound it: the caller requires
// `email_verified` from the IdP before calling at all, and the predicate below
// means it can happen ONCE. A user already linked to a different subject is not
// relinked — the UPDATE matches nothing and the login is refused, rather than
// the newer assertion winning.
//
// ErrNotFound therefore means "already linked, or no such user", which are the
// same answer to the caller: this login does not get that account.
func (Users) LinkSubject(ctx context.Context, c *Conn, userID uuid.UUID, subject string) error {
	if subject == "" {
		return errors.New("store: cannot link an empty oidc subject")
	}
	const q = `
		UPDATE users SET oidc_subject = $3
		 WHERE tenant_id = $1 AND user_id = $2 AND oidc_subject IS NULL
		RETURNING user_id`

	var got uuid.UUID
	return mapError(c.QueryRow(ctx, q, c.Tenant().UUID(), userID, subject).Scan(&got))
}
