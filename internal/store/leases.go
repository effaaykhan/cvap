package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// LeaseState mirrors the lease_state enum.
type LeaseState string

const (
	LeaseGranted  LeaseState = "granted"
	LeaseLost     LeaseState = "lost"
	LeaseExpired  LeaseState = "expired"
	LeaseReleased LeaseState = "released"
)

// Lease TTLs, per execution-plan §5.
//
// The scan point renews at 20s against a 60s TTL, so two consecutive renewals
// can be lost before the lease expires. The TTL is Core's and the scan point
// cannot ask for longer — LeaseRenewal deliberately carries no requested
// duration, because letting a compromised scan point extend it would extend the
// window credential material lives in its memory (ADR-020).
const (
	LeaseTTL             = 60 * time.Second
	LeaseRenewalInterval = 20 * time.Second
)

// Lease is one generation of a job's assignment.
//
// job_leases is append-only: one row per generation, not one row per job. The
// case you need the table for is a fencing failure — two scan points both
// believing they hold the same job — and overwriting the row on reassignment
// destroys exactly the history that investigation needs.
type Lease struct {
	ID        uuid.UUID
	JobID     uuid.UUID
	Epoch     int64
	HolderID  uuid.UUID
	State     LeaseState
	GrantedAt time.Time
	ExpiresAt time.Time
	RenewedAt *time.Time
}

type Leases struct{}

// Grant issues a lease for a job at the next epoch.
//
// The epoch is allocated as max+1 for that job. That is safe because the caller
// holds the job row's lock — Jobs.Claim took it FOR UPDATE in the same
// transaction — so no second dispatcher can be allocating for this job at the
// same time. UNIQUE (tenant_id, job_id, epoch) is the backstop: the lock gives
// correctness, the constraint gives proof, and if the two ever disagree one
// transaction dies rather than two scan points sharing an epoch.
//
// Monotonic, and never reused. A reassignment issues a HIGHER epoch and only
// after demonstrable expiry (ADR-012), which is what makes the epoch a fencing
// token rather than a label.
func (Leases) Grant(ctx context.Context, c *Conn, jobID, holderID uuid.UUID, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		ttl = LeaseTTL
	}

	const q = `
		INSERT INTO job_leases
		    (tenant_id, job_id, epoch, holder_scan_point, state, expires_at)
		VALUES (
		    $1, $2,
		    coalesce((SELECT max(epoch) FROM job_leases
		               WHERE tenant_id = $1 AND job_id = $2), 0) + 1,
		    $3, 'granted', clock_timestamp() + $4::interval
		)
		RETURNING lease_id, job_id, epoch, holder_scan_point, state,
		          granted_at, expires_at, renewed_at`

	var l Lease
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), jobID, holderID, ttl.String()).
		Scan(&l.ID, &l.JobID, &l.Epoch, &l.HolderID, &l.State,
			&l.GrantedAt, &l.ExpiresAt, &l.RenewedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &l, nil
}

// Renew extends a lease, and is the fencing check.
//
// ============================================================================
// Zero rows is the refusal, and the refusal is the whole control.
// ============================================================================
//
// Every clause in the predicate refuses something specific:
//
//	epoch = $3              a superseded epoch does not match. This is the
//	                        fencing token doing its job (ADR-012).
//	holder_scan_point = $4  taken from the TLS PEER CERTIFICATE, never from the
//	                        message. Without it one scan point could renew
//	                        another's lease — a fencing bypass that looks like
//	                        an ordinary liveness message.
//	state = 'granted'       a lease already marked lost or expired does not come
//	                        back. This is what makes reassignment safe against a
//	                        concurrent renewal: ExpireLeases marks the row
//	                        'expired', and a renewal that blocks on the row lock
//	                        re-evaluates this clause afterwards and matches
//	                        nothing.
//
//	                        Note what this does NOT say. Expiry and the new
//	                        grant are separate transactions — ExpireLeases
//	                        expires, and a later offerWork grants. An earlier
//	                        version of this comment claimed they were one, which
//	                        was a tidier story and false. The property holds
//	                        anyway, from this clause and the expiry clause
//	                        below, and it is verified under forced interleaving
//	                        in TestRenewalRefusedAfterSupersession.
//	expires_at > now()      an expired lease is not renewable. A reassignment may
//	                        already be in flight, and extending it would put two
//	                        scan points on one job.
//
// clock_timestamp() rather than now(): now() is transaction_timestamp() and
// returns when the transaction began, so after a lock wait the predicate would
// be evaluated against a stale reading and an expired lease could still renew.
//
// Returns ErrNotFound on refusal. The caller reads afterwards ONLY to choose the
// operator-facing message between LOST and UNKNOWN_JOB — the decision is already
// made here.
func (Leases) Renew(ctx context.Context, c *Conn, jobID uuid.UUID, epoch int64, holderID uuid.UUID, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		ttl = LeaseTTL
	}

	const q = `
		UPDATE job_leases
		   SET renewed_at = clock_timestamp(),
		       expires_at = clock_timestamp() + $5::interval
		 WHERE tenant_id = $1
		   AND job_id = $2
		   AND epoch = $3
		   AND holder_scan_point = $4
		   AND state = 'granted'
		   AND expires_at > clock_timestamp()
		RETURNING lease_id, job_id, epoch, holder_scan_point, state,
		          granted_at, expires_at, renewed_at`

	var l Lease
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), jobID, epoch, holderID, ttl.String()).
		Scan(&l.ID, &l.JobID, &l.Epoch, &l.HolderID, &l.State,
			&l.GrantedAt, &l.ExpiresAt, &l.RenewedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &l, nil
}

// ReleaseAny ends a lease without a holder check.
//
// For Core-side callers only — an operator action or a sweep, where there is no
// scan point identity to check against. Never reachable from a scan point
// message: if a wire handler needs this, it needs Release instead.
func (Leases) ReleaseAny(ctx context.Context, c *Conn, jobID uuid.UUID, epoch int64, state LeaseState) error {
	const q = `
		UPDATE job_leases SET state = $4
		 WHERE tenant_id = $1 AND job_id = $2 AND epoch = $3 AND state = 'granted'`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, epoch, string(state))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Current returns the highest epoch for a job, whatever its state.
//
// This is what ingest compares a submission's epoch against (ADR-026). It
// returns the lease regardless of state on purpose: a submission arriving after
// the lease was released is not superseded, and treating "released" as "no
// lease" would quarantine every result from a job that finished normally.
func (Leases) Current(ctx context.Context, c *Conn, jobID uuid.UUID) (*Lease, error) {
	const q = `
		SELECT lease_id, job_id, epoch, holder_scan_point, state,
		       granted_at, expires_at, renewed_at
		  FROM job_leases
		 WHERE tenant_id = $1 AND job_id = $2
		 ORDER BY epoch DESC
		 LIMIT 1`

	var l Lease
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), jobID).
		Scan(&l.ID, &l.JobID, &l.Epoch, &l.HolderID, &l.State,
			&l.GrantedAt, &l.ExpiresAt, &l.RenewedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &l, nil
}

// Release ends a lease normally, when its job terminates.
//
// holderID is in the predicate for the same reason it is in Renew: job_id and
// epoch both arrive from the scan point, and without the holder any scan point
// in the tenant could release another's lease — which fences that scan point off
// its own job. Renew had this clause from the start; Release and Terminate did
// not, and a security review proved the gap was reachable.
//
// ReleaseAny is the Core-side variant for a caller that is not a scan point.
func (Leases) Release(ctx context.Context, c *Conn, jobID uuid.UUID, epoch int64, holderID uuid.UUID, state LeaseState) error {
	const q = `
		UPDATE job_leases SET state = $5
		 WHERE tenant_id = $1 AND job_id = $2 AND epoch = $3
		   AND holder_scan_point = $4 AND state = 'granted'`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), jobID, epoch, holderID, string(state))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpireLeases is where at-most-once is won or lost.
//
// ============================================================================
// reassign_safe decides whether a job goes back in the queue. Nothing else.
// ============================================================================
//
// A lease that ran out means the scan point stopped renewing: it died, its
// network partitioned, or it self-aborted. The job is not finished, and there
// are exactly two right answers depending on what re-running it would cost.
//
//	reassign_safe        back to 'queued'. Passive discovery is safe to
//	                     duplicate, dedup absorbs the overlap (ADR-010), and a
//	                     retry supersedes the incomplete attempt.
//
//	NOT reassign_safe    'failed' with termination_reason = 'lease_lost', and
//	                     an operator escalation. Active DAST, intrusive checks
//	                     and anything credentialed that changes state must fail
//	                     LOUDLY rather than silently retry, because duplicating
//	                     the work harms the target (ADR-012).
//
// Re-queuing everything is the bug this function exists to not have. It would
// look correct in every test that did not distinguish the two, and the damage
// would land on a customer's estate rather than in our logs.
//
// The lease row is marked 'expired' either way — the results that job already
// submitted are retained regardless, because reassign_safe governs retry and not
// retention (ADR-026).
func (Leases) ExpireLeases(ctx context.Context, c *Conn, limit int) ([]ExpiredLease, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	const q = `
		WITH expired AS (
		    UPDATE job_leases l
		       SET state = 'expired'
		     WHERE l.tenant_id = $1
		       AND l.state = 'granted'
		       AND l.expires_at <= clock_timestamp()
		       AND l.lease_id IN (
		           SELECT lease_id FROM job_leases
		            WHERE tenant_id = $1 AND state = 'granted'
		              AND expires_at <= clock_timestamp()
		            ORDER BY expires_at
		            LIMIT $2
		            FOR UPDATE SKIP LOCKED
		       )
		    RETURNING l.job_id, l.epoch, l.holder_scan_point
		)
		UPDATE scan_jobs j
		   SET status = CASE WHEN j.reassign_safe THEN 'queued'::job_status
		                     ELSE 'failed'::job_status END,
		       scan_point_id = CASE WHEN j.reassign_safe THEN NULL
		                            ELSE j.scan_point_id END,
		       termination_reason = CASE WHEN j.reassign_safe THEN j.termination_reason
		                                 ELSE 'lease_lost'::termination_reason END,
		       completed_at = CASE WHEN j.reassign_safe THEN NULL ELSE now() END
		  FROM expired
		 WHERE j.tenant_id = $1
		   AND j.job_id = expired.job_id
		   AND j.status IN ('assigned', 'running')
		RETURNING j.job_id, expired.holder_scan_point, expired.epoch,
		          j.reassign_safe, j.reassign_safe AS requeued`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ExpiredLease
	for rows.Next() {
		var e ExpiredLease
		if err := rows.Scan(&e.JobID, &e.ScanPointID, &e.Epoch, &e.ReassignSafe, &e.Requeued); err != nil {
			return nil, mapError(err)
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}
