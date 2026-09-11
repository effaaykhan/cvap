package store

import (
	"context"
	"errors"

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
