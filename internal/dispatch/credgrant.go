package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/credsource"
	"github.com/effaaykhan/cvap/internal/hostkeytrust"
	"github.com/effaaykhan/cvap/internal/sshalgo"
	"github.com/effaaykhan/cvap/internal/store"
)

// CredentialGrantTTL bounds how long a grant may be USED TO START an engine. The
// runtime refuses to spawn against an expired grant and zeroises at the job's end
// regardless (ADR-020); this is the outer bound on the window between Core
// resolving the secret and the runtime either using it or dropping it. Short
// because the job it belongs to has already been claimed and assigned on the same
// pass — a grant that cannot be consumed within this is a grant to a scan point
// that is not reading its stream.
const CredentialGrantTTL = 10 * time.Minute

// UseSecretResolver installs the resolver that turns a profile's secret_ref into
// grant material. Without one every credentialed-host job is refused with an
// audit event naming the missing configuration, which is the correct shape for
// a deployment that has not decided where its secrets live: refuse loudly, never
// scan uncredentialed under a policy that authorised credentials.
func (s *Service) UseSecretResolver(r credsource.Resolver) { s.secrets = r }

// errCredentialRefused marks a host job Core will not dispatch because it
// cannot be credentialed as its policy requires. The wrapped text says why.
var errCredentialRefused = errors.New("dispatch: credentialed job refused")

// pendingGrant is a resolved secret on its way to the wire, and the ONE place in
// Core the material exists between the resolver returning and stream.Send
// marshalling it.
//
// Every path that does not end in Send must call discard: the transaction that
// claimed the job rolling back, the assignment being dropped by a full queue, or
// the grant itself being dropped. The message's own byte slice is what discard
// erases, so there is exactly one array to reach (the same argument ADR-038
// makes for the runtime's Credential).
type pendingGrant struct {
	assignment *scanpointv1.JobAssignment
	grant      *scanpointv1.CredentialGrant

	// queued is set once the grant is on the outbound channel. From then on
	// the send loop owns the erase (eraseGrantMaterial, after Send), and the
	// producer's deferred discard must NOT touch it: the first version erased
	// every grant when offerWork returned, which is before the send loop had
	// dequeued it, so the runtime received a grant of zeros. A test that read
	// the bytes at Send caught it.
	queued bool
}

func (p *pendingGrant) discard() {
	if p == nil || p.grant == nil {
		return
	}
	clear(p.grant.Material)
	p.grant.Material = nil
}

// eraseGrantMaterial is called by the send loop after stream.Send has returned
// for a CoreMessage carrying a grant — success or failure. Once the bytes are in
// the transport's buffer (or the send failed and never will be), Core's copy has
// no further purpose, and the decoded message would otherwise hold the secret
// until the garbage collector got to it.
//
// THIS MUTATES A MESSAGE ALREADY PASSED TO SendMsg, WHICH gRPC DOCUMENTS AS
// UNSAFE. Not inferred — google.golang.org/grpc@v1.83.1 stream.go:1632, on the
// ServerStream interface: "It is not safe to modify the message after calling
// SendMsg. Tracing libraries and stats handlers may use the message lazily."
// SendMsg also only blocks until there is flow control to schedule the message
// (stream.go:1620), so "the bytes are in the transport's buffer" is a claim
// about grpc-go's current behaviour, not about its contract.
//
// It is deliberate, and it is a trade, not an oversight: the alternative is a
// released secret sitting in a decoded message for an unbounded time, which
// non-negotiable #8 exists to prevent. What makes it safe TODAY is that this
// server installs no stats handler and no interceptor (cmd/cvap-core/main.go
// builds mtlsServer with Creds and KeepaliveParams only), so nothing else holds
// a reference to read. That is a latent limitation, not a dormant defect: the
// day an observability change adds a StatsHandler, a tracing interceptor or a
// message-logging middleware, this becomes a live read of freed-in-place bytes.
// Whoever adds one must move the erase (a codec that zeroises after marshal, or
// a message Core owns and the transport copies from) in the same change.
func eraseGrantMaterial(msg *scanpointv1.CoreMessage) {
	if g := msg.GetCredential(); g != nil {
		clear(g.Material)
		g.Material = nil
	}
}

// credentialedAssignment completes a host job's assignment: the non-secret
// cred_user and known_hosts on the JobAssignment, a credential_grants row, an
// audit event recording the trust-source claim, and the CredentialGrant that
// follows the assignment on the wire.
//
// The ORDER inside is deliberate. Everything that can refuse the job runs
// before the secret is resolved — no profile, no username, no trust material —
// so that the resolve-then-refuse window is as narrow as the code can make it:
// after Resolve, the only things left are the grant row and the audit event, and
// both failures are transaction errors that the caller's discard covers. A
// refusal returns errCredentialRefused (wrapped) and the caller ends the job with
// refuseCredentialedJob; any other error aborts the pass.
func (s *Service) credentialedAssignment(ctx context.Context, c *store.Conn, sess *session,
	j store.Job, tasks []store.Task, wire *scanpointv1.JobAssignment,
) (*pendingGrant, error) {
	if s.secrets == nil {
		return nil, fmt.Errorf("%w: Core has no secret resolver configured (CVAP_CORE_SECRET_FILE_ROOT)", errCredentialRefused)
	}

	profile, found, err := (store.CredentialProfiles{}).SSHForJob(ctx, c, j.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: the policy authorises no ssh credential profile", errCredentialRefused)
	}
	if profile.Username == "" {
		return nil, fmt.Errorf("%w: credential profile %s has no username", errCredentialRefused, profile.ID)
	}

	// The trust material and its source. Operator-pinned lines win outright;
	// otherwise every task must have a host key CVAP observed, and one without
	// is a refusal for the whole job rather than a TOFU for that host.
	src, material, err := s.trustMaterial(ctx, c, profile, tasks)
	if err != nil {
		return nil, err
	}
	knownHosts, err := hostkeytrust.Compose(src, material)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCredentialRefused, err)
	}

	// Last, and only once nothing above can refuse.
	secret, err := s.secrets.Resolve(ctx, profile.SecretRef)
	if err != nil {
		// The cause, never the ref or its path, reaches the audit log:
		// credsource strips the path from its errors for that reason, and
		// this wrapping adds nothing that would put it back.
		return nil, fmt.Errorf("%w: secret_ref could not be resolved: %w", errCredentialRefused, err)
	}
	scope := make([]string, 0, len(tasks))
	for _, t := range tasks {
		scope = append(scope, t.TaskTarget)
	}
	grant := &scanpointv1.CredentialGrant{
		JobId:    j.ID.String(),
		Material: secret,
		Scope:    scope,
		CredKind: scanpointv1.CredKind_RAW_SECRET,
	}
	pending := &pendingGrant{assignment: wire, grant: grant}

	// The expiry is the database's clock plus the TTL, not this process's:
	// the row's CHECK compares it against issued_at on that clock.
	grantID, expires, err := (store.CredentialGrants{}).Issue(ctx, c, store.GrantIssue{
		ProfileID:              profile.ID,
		JobID:                  j.ID,
		Kind:                   store.CredKindRawSecret,
		TargetScope:            scope,
		DeliveredToFingerprint: sess.fingerprint,
		TTL:                    CredentialGrantTTL,
	})
	if err != nil {
		pending.discard()
		return nil, err
	}
	grant.GrantId = grantID.String()
	grant.ExpiresUnix = expires.Unix()

	// The claim the runtime enforces and the auditor reads, in the same
	// transaction as the release it describes. No material, no ref: the
	// profile id is the pointer an auditor follows.
	jobID := j.ID
	if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
		ActorType:    store.ActorSystem,
		Action:       "credential.granted",
		ResourceType: "scan_job",
		ResourceID:   &jobID,
		Detail: map[string]any{
			"grant_id":              grantID.String(),
			"credential_profile_id": profile.ID.String(),
			"cred_kind":             string(store.CredKindRawSecret),
			"cred_user":             profile.Username,
			"trust_source":          string(src),
			"targets":               len(scope),
			"scan_point_id":         sess.spID.String(),
			"scan_id":               j.ScanID.String(),
			"expires_at":            expires.UTC().Format(time.RFC3339),
		},
	}); err != nil {
		pending.discard()
		return nil, err
	}

	wire.CredUser = profile.Username
	wire.KnownHosts = knownHosts
	return pending, nil
}

// fingerprintShape is the only thing an observed ssh_hostkey value may look
// like on its way into the wire field. asset_identity_keys.key_value is
// unbounded text written from an observation a scan point submitted; a value
// that passed a mere prefix check but carried a newline composed extra
// known_hosts lines for OTHER hosts — a compromised scan point in one zone
// poisoning the trust material of a credentialed job in another (security
// review, ADR-091). One token, one shape, nothing else.
var fingerprintShape = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/=]{20,100}$`)

// trustMaterial picks the trust source for a job and gathers its lines — for
// each task, exactly the lines that cover THAT task's address.
//
// An operator pin wins outright when present, but it must cover every task:
// the lines whose host field names the task's address are what travel, and a
// task no line covers refuses the job. The first version passed the whole pin
// verbatim, so a pin written for one host was trusted for every host in the
// job (scan-safety audit, ADR-091). Without a pin, every task must have a host
// key CVAP observed, and one without refuses the whole job rather than a TOFU
// for that host.
func (s *Service) trustMaterial(ctx context.Context, c *store.Conn, profile *store.SSHCredentialProfile, tasks []store.Task) (hostkeytrust.Source, string, error) {
	if strings.TrimSpace(profile.KnownHosts) != "" {
		var b strings.Builder
		for _, t := range tasks {
			covered := hostkeytrust.LinesCovering(profile.KnownHosts, t.TaskTarget)
			if len(covered) == 0 {
				return "", "", fmt.Errorf("%w: the operator-pinned known_hosts has no line for task %s target %q",
					errCredentialRefused, t.ID, t.TaskTarget)
			}
			for _, line := range covered {
				b.WriteString(line)
				b.WriteString("\n")
			}
		}
		return hostkeytrust.SourceOperator, b.String(), nil
	}
	var b strings.Builder
	for _, t := range tasks {
		addr, err := netip.ParseAddr(t.TaskTarget)
		if err != nil {
			// asset_addresses keys on ip_address; a hostname target has no
			// observed key to look up. Not a TOFU: a refusal.
			return "", "", fmt.Errorf("%w: task %s target %q is not an address, and no operator-pinned known_hosts covers it",
				errCredentialRefused, t.ID, t.TaskTarget)
		}
		// The port the engine dials. No job names one today (credhost's
		// Config.Port is never set), so this constant IS the engine's port;
		// the day an assignment carries a port, this must follow it or the
		// verification fails closed against the wrong service's key (ADR-094).
		fps, err := (store.AssetIdentityKeys{}).SSHHostKeyFingerprintsAt(ctx, c, addr.String(), sshalgo.DefaultPort, store.SightingWindow)
		if err != nil {
			return "", "", err
		}
		if len(fps) == 0 {
			return "", "", fmt.Errorf("%w: no ssh host key seen at task %s target %q on two distinct scans (ADR-094) and no operator-pinned known_hosts; trust-on-first-use is not permitted",
				errCredentialRefused, t.ID, t.TaskTarget)
		}
		if len(fps) > 1 {
			// Two distinct host keys qualifying at one address and port is
			// the handover signature itself (ADR-094): whichever machine
			// answers would be accepted. Refuse rather than compose two lines.
			return "", "", fmt.Errorf("%w: %d distinct ssh host keys qualify at task %s target %q on the dialled port; two hosts have been seen there and neither is trusted",
				errCredentialRefused, len(fps), t.ID, t.TaskTarget)
		}
		for _, fp := range fps {
			if !fingerprintShape.MatchString(fp) {
				// What discovery stores is a SHA256 fingerprint (ADR-091 §1),
				// and nothing else may compose a line: a prefix check let a
				// value with embedded newlines through. Refuse here, where the
				// refusal is audited, rather than in the engine.
				return "", "", fmt.Errorf("%w: observed ssh host key for %q is not a well-formed SHA256 fingerprint",
					errCredentialRefused, t.TaskTarget)
			}
			b.WriteString(addr.String())
			b.WriteString(" ")
			b.WriteString(fp)
			b.WriteString("\n")
		}
	}
	return hostkeytrust.SourceObserved, b.String(), nil
}

// refuseCredentialedJob ends a host job Core cannot credential, and records why.
//
// Terminal for the reason refuseJob is: the refusal is identical on every poll.
// engine_failure rather than scope_violation_halt, because nothing about scope
// is wrong — the job is refused before an engine exists, which is the "refused
// the job" half of that reason's definition. The audit action is its own, so an
// operator filtering for credential problems finds them without reading detail.
//
// Returns the audit event it recorded so the caller can replay it if the pass's
// transaction rolls back after this point.
func (s *Service) refuseCredentialedJob(ctx context.Context, c *store.Conn, jobID, spID uuid.UUID, policy *store.JobPolicy, why string) (store.AuditEvent, error) {
	s.log.ErrorContext(ctx, "host job refused: it cannot be credentialed",
		slog.String("job_id", jobID.String()),
		slog.String("scan_point_id", spID.String()),
		slog.String("policy_id", policy.ID.String()),
		slog.String("reason", why))

	if err := (store.Jobs{}).Terminate(ctx, c, jobID, spID, store.TerminationEngineFailure, false); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		return store.AuditEvent{}, err
	}
	id := jobID
	ev := store.AuditEvent{
		ActorType:    store.ActorSystem,
		Action:       "job.credential_refused",
		ResourceType: "scan_job",
		ResourceID:   &id,
		Detail: map[string]any{
			"policy_id":     policy.ID.String(),
			"policy":        policy.Name,
			"reason":        why,
			"scan_point_id": spID.String(),
		},
	}
	return ev, (store.AuditEvents{}).Record(ctx, c, ev)
}
