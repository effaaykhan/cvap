package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CredentialProfiles reads the credential profiles a scan policy authorises.
// It never returns secret material: secret_ref is a vault pointer (ADR-020,
// migration 0004), resolved to bytes elsewhere and only at grant time.
type CredentialProfiles struct{}

// SSHCredentialProfile is the non-secret shape the dispatch producer needs to build
// a credentialed-host grant: the pointer to resolve, the user to authenticate as,
// and any operator-pinned host keys. The key material itself is never here.
type SSHCredentialProfile struct {
	ID         uuid.UUID
	SecretRef  string // scheme:// pointer, resolved at grant time
	Username   string // "" when the profile set none — the caller must refuse
	KnownHosts string // operator override; "" means use the observed host key
}

// SSHForJob returns the ssh credential profile a job's policy authorises, if any.
//
// The join walks job -> scan -> policy -> the many-to-many authorisation table ->
// profile, all tenant-qualified so a policy in one tenant cannot reach another's
// profile even if IDs are confused (the composite FKs in migration 0004 enforce the
// same). `found` is false with a nil profile when the policy authorises no ssh
// profile — the caller decides whether that is fine (an uncredentialed job) or a
// refusal (a host job that needs one).
//
// A policy may authorise more than one ssh profile; this returns the earliest
// authorised (then by name) deterministically rather than guessing intent. Choosing
// among several for one job is an operator-API concern, not the dispatcher's.
func (CredentialProfiles) SSHForJob(ctx context.Context, c *Conn, jobID uuid.UUID) (*SSHCredentialProfile, bool, error) {
	const q = `
		SELECT cp.credential_profile_id, cp.secret_ref,
		       coalesce(cp.username, ''), coalesce(cp.known_hosts, '')
		  FROM scan_jobs j
		  JOIN scans s
		    ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		  JOIN scan_policy_credential_profiles spcp
		    ON spcp.tenant_id = s.tenant_id AND spcp.policy_id = s.policy_id
		  JOIN credential_profiles cp
		    ON cp.tenant_id = spcp.tenant_id
		   AND cp.credential_profile_id = spcp.credential_profile_id
		 WHERE j.tenant_id = $1 AND j.job_id = $2
		   AND cp.cred_type = 'ssh'
		 ORDER BY spcp.authorized_at, cp.name
		 LIMIT 1`

	var p SSHCredentialProfile
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), jobID).
		Scan(&p.ID, &p.SecretRef, &p.Username, &p.KnownHosts)
	if err != nil {
		if mapped := mapError(err); errors.Is(mapped, ErrNotFound) {
			return nil, false, nil // no ssh profile authorised for this job
		}
		return nil, false, mapError(err)
	}
	return &p, true, nil
}

// CredentialProfileSummary is a profile's non-secret face: what an operator
// sees to choose one and to see whether it carries a pin (ADR-100). Never the
// secret, never the pointer.
type CredentialProfileSummary struct {
	ID        uuid.UUID
	Name      string
	CredType  string
	Username  string
	PinLines  int // known_hosts lines pinned by an operator; 0 = the observed key is used
	UpdatedAt time.Time
}

// List returns the tenant's credential profiles, by name.
func (CredentialProfiles) List(ctx context.Context, c *Conn) ([]CredentialProfileSummary, error) {
	const q = `
		SELECT credential_profile_id, name, cred_type::text, coalesce(username, ''),
		       coalesce(array_length(string_to_array(trim(both E'\n' from known_hosts), E'\n'), 1), 0),
		       updated_at
		  FROM credential_profiles
		 WHERE tenant_id = $1
		 ORDER BY name`
	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []CredentialProfileSummary
	for rows.Next() {
		var p CredentialProfileSummary
		if err := rows.Scan(&p.ID, &p.Name, &p.CredType, &p.Username, &p.PinLines, &p.UpdatedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, p)
	}
	return out, mapError(rows.Err())
}

// GetByName resolves a profile by its tenant-unique name.
func (CredentialProfiles) GetByName(ctx context.Context, c *Conn, name string) (*CredentialProfileSummary, error) {
	all, err := (CredentialProfiles{}).List(ctx, c)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, ErrNotFound
}

// SetKnownHosts writes an operator pin — validated by the caller with
// hostkeytrust.ValidatePin — or clears it with "" (NULL: the observed key is
// used again). The pin outranks the observed key outright (ADR-091 §4), so
// the write is the trust decision and the caller records it. ErrNotFound for
// a profile the tenant does not hold.
func (CredentialProfiles) SetKnownHosts(ctx context.Context, c *Conn, id uuid.UUID, material string, at time.Time) error {
	var m any
	if material != "" {
		m = material
	}
	tag, err := c.Exec(ctx, `UPDATE credential_profiles SET known_hosts = $3, updated_at = $4 WHERE tenant_id = $1 AND credential_profile_id = $2`,
		c.Tenant().UUID(), id, m, at)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CredentialGrants is the release record migration 0006 keeps: one row per
// delivery of credential material to a scan point (ADR-020). It never holds the
// material — the row is the account of a secret having left Core, not a cache.
type CredentialGrants struct{}

// CredKind mirrors cred_kind (migration 0006) and CredKind on the wire.
type CredKind string

const (
	CredKindRawSecret CredKind = "raw_secret"
)

// GrantIssue is what Issue records.
type GrantIssue struct {
	ProfileID uuid.UUID
	JobID     uuid.UUID
	Kind      CredKind
	// TargetScope is the targets the material may be used against — the job's
	// task targets. Recorded so an auditor can answer "what could this have been
	// used against" after the task list is pruned.
	TargetScope []string
	// DeliveredToFingerprint is the scan point's certificate fingerprint — what
	// the TLS layer actually authenticated, rather than the id it echoed.
	DeliveredToFingerprint string
	// TTL is added to the DATABASE's now() to produce expires_at, so the
	// CHECK (expires_at > issued_at) — issued_at defaults to the same clock —
	// cannot fail on a Core whose clock is behind the database. A skew that
	// large stopped every assignment for the scan point, silently, in the
	// first version (security review, ADR-091).
	TTL time.Duration
}

// Issue records a release and returns the grant id and expiry that travel on
// the wire.
//
// Written in the same transaction as the lease and the assignment, so a grant
// row exists for exactly the grants that were built — a row with no grant on the
// wire is an auditor chasing a delivery that never happened, and a grant with no
// row is a delivery nobody can account for.
func (CredentialGrants) Issue(ctx context.Context, c *Conn, g GrantIssue) (uuid.UUID, time.Time, error) {
	if g.Kind == "" {
		return uuid.Nil, time.Time{}, errors.New("store: credential grant needs a cred_kind")
	}
	if g.DeliveredToFingerprint == "" {
		return uuid.Nil, time.Time{}, errors.New("store: credential grant needs the receiving scan point's fingerprint")
	}
	if g.TTL <= 0 {
		return uuid.Nil, time.Time{}, errors.New("store: credential grant needs a positive TTL")
	}
	scope, err := json.Marshal(g.TargetScope)
	if err != nil {
		return uuid.Nil, time.Time{}, fmt.Errorf("store: marshal grant scope: %w", err)
	}
	const q = `
		INSERT INTO credential_grants
		    (tenant_id, credential_profile_id, job_id, cred_kind, target_scope,
		     delivered_to_fingerprint, expires_at)
		VALUES ($1, $2, $3, $4::text::cred_kind, $5, $6, now() + make_interval(secs => $7))
		RETURNING grant_id, expires_at`
	var id uuid.UUID
	var expires time.Time
	err = c.QueryRow(ctx, q, c.Tenant().UUID(), g.ProfileID, g.JobID, string(g.Kind),
		scope, g.DeliveredToFingerprint, g.TTL.Seconds()).Scan(&id, &expires)
	if err != nil {
		return uuid.Nil, time.Time{}, mapError(err)
	}
	return id, expires, nil
}

// MarkZeroised records the scan point's attestation for every grant of a job
// that was delivered to THAT scan point and has not already confirmed.
// Idempotent; a job with no grants is not an error, because most jobs carry none.
//
// zeroised_at is set only from the attestation, never from the terminal alone —
// a narrowing of migration 0006's comment, which also names "Core observes the
// job terminate": NULL means "we have no confirmation", which is the
// operator-visible state a JobTerminal without credentials_zeroised must leave
// behind rather than paper over. And only for the recipient: the fingerprint is
// what the TLS layer authenticated, so a scan point that never received a grant
// cannot close the record of it by naming the job.
// MarkDelivered records that a grant's material actually reached the outbound
// stream (ADR-101's class, 0053).
//
// Separate from Issue because issue and delivery are two facts and the row used
// to carry only the first while the audit asserted the second. Measured at 4 of 9
// trials: the transaction commits, `trySend` then finds the outbound queue full,
// the material is erased, and nothing had recorded that it never went.
//
// Idempotent on the first write — `delivered_at IS NULL` in the predicate — so a
// retry cannot move the timestamp forward and make a late delivery look prompt.
func (CredentialGrants) MarkDelivered(ctx context.Context, c *Conn, grantID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE credential_grants
		   SET delivered_at = $3
		 WHERE tenant_id = $1 AND grant_id = $2 AND delivered_at IS NULL`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), grantID, at.UTC())
	return mapError(err)
}

// Undelivered lists grants that were issued and never reached a scan point. The
// question an operator asks after a dispatch storm, and the reason delivery is a
// column rather than the absence of a second audit event: a state derived by
// joining one event against the absence of another is one every caller
// re-derives differently.
func (CredentialGrants) Undelivered(ctx context.Context, c *Conn, limit int) ([]uuid.UUID, error) {
	const q = `
		SELECT grant_id FROM credential_grants
		 WHERE tenant_id = $1 AND delivered_at IS NULL
		 ORDER BY issued_at DESC LIMIT $2`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), limit)
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

func (CredentialGrants) MarkZeroised(ctx context.Context, c *Conn, jobID uuid.UUID, deliveredToFingerprint string, at time.Time) error {
	if deliveredToFingerprint == "" {
		return errors.New("store: MarkZeroised needs the attesting scan point's fingerprint")
	}
	const q = `
		UPDATE credential_grants
		   SET zeroised_at = $4
		 WHERE tenant_id = $1 AND job_id = $2 AND delivered_to_fingerprint = $3
		   AND zeroised_at IS NULL`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, deliveredToFingerprint, at)
	return mapError(err)
}

// Unconfirmed is the incident question: grants past expiry that never confirmed
// zeroisation. Bounded, newest first.
func (CredentialGrants) Unconfirmed(ctx context.Context, c *Conn, now time.Time, limit int) ([]uuid.UUID, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	const q = `
		SELECT grant_id FROM credential_grants
		 WHERE tenant_id = $1 AND zeroised_at IS NULL AND expires_at < $2
		 ORDER BY expires_at DESC
		 LIMIT $3`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), now, limit)
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
