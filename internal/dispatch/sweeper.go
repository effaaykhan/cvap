package dispatch

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// Sweeper is the caller ADR-012 assumed existed.
//
// ============================================================================
// A property with no caller is a property that is not enforced.
// ============================================================================
//
// Leases.ExpireLeases carries the whole at-most-once decision: a reassign_safe
// job whose lease ran out goes back to the queue, and one that is NOT
// reassign_safe fails with termination_reason = 'lease_lost' and an operator
// escalation, because duplicating active or intrusive work harms the target.
// It was written, documented at length, tested — and never called. A security
// review found it. Nothing in Core would ever have expired a lease, so a scan
// point that died mid-job left that job 'running' forever: never retried when
// retry was safe, and never escalated when it was not.
//
// The same review found HeartbeatTimeout in the same state — a constant, a
// comment saying "Core times out at 90s", and no comparison anywhere.
//
// The sweep is periodic rather than event-driven for a reason that is not
// convenience: the event it reacts to is the ABSENCE of one. A scan point that
// dies sends nothing, and the stream closing is not the signal either — a
// partitioned scan point holds its lease and keeps working while its stream is
// long gone. Only the clock knows.
type Sweeper struct {
	db  *store.DB
	log *slog.Logger

	// Interval is how often every active tenant is swept.
	//
	// Bounded below by nothing useful and above by the lease TTL: a sweep slower
	// than the TTL means an expired lease stays 'granted' for up to one interval,
	// which delays a reassign_safe job's requeue and — worse — delays the
	// operator escalation on a job that must not retry.
	Interval time.Duration

	// BatchLimit bounds one tenant's expiry pass, so a tenant with a large
	// backlog cannot hold the transaction open across the whole fleet.
	BatchLimit int

	now func() time.Time
}

func NewSweeper(db *store.DB, log *slog.Logger) *Sweeper {
	return &Sweeper{db: db, log: log, Interval: 10 * time.Second, BatchLimit: 100, now: time.Now}
}

// Run sweeps until ctx is cancelled.
//
// It never returns an error. A sweep that fails must not stop the loop: the
// failure modes are a transient database error and one tenant's transaction
// losing a race, and a supervisor that restarted the process on either would
// turn a recoverable blip into an outage of the thing that enforces ADR-012.
// Failures are logged and the next tick tries again.
func (s *Sweeper) Run(ctx context.Context) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep(ctx)
		}
	}
}

// Sweep runs one pass over every active tenant. Exported so a test can drive a
// single deterministic pass rather than racing a ticker.
func (s *Sweeper) Sweep(ctx context.Context) {
	tenants, err := s.db.ActiveTenantIDs(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "sweep: enumerate tenants", "error", err)
		return
	}
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return
		}
		s.sweepTenant(ctx, tenant)

		// Planning runs in its own transactions, AFTER the lease pass.
		//
		// Not folded into sweepTenant's transaction: planning a /16 writes
		// 65,536 rows, and holding the lease-expiry transaction open for that
		// would delay ADR-012's at-most-once enforcement behind an operator's
		// large scan.
		//
		// It is still SERIAL with the lease pass, and that is a decision rather
		// than an oversight. This package's CLAUDE.md requires Interval to stay
		// below store.LeaseTTL, because a sweep slower than the TTL delays the
		// escalation on a job that must not retry — and planning work can now
		// push a PASS past the interval whatever Interval is set to. Accepted
		// because the alternative, a second ticker, means two goroutines writing
		// to the same tenant's rows on independent schedules, and the ordering
		// between "this scan was cancelled" and "this scan was planned" stops
		// being decided by one loop. PlanBatchLimit bounds how far one tenant can
		// push a pass; if that stops being enough, the fix is a separate ticker
		// with the ordering thought through, not a bigger limit.
		PlanPending(ctx, s.db, s.log, tenant, PlanBatchLimit)
	}
}

func (s *Sweeper) sweepTenant(ctx context.Context, tenant store.TenantID) {
	var expired []store.ExpiredLease
	var offline []uuid.UUID

	err := s.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		// Leases first. A scan point marked offline is a display fact; a lease
		// expired is a job that moves. Doing the lease pass first means a crash
		// between the two leaves the operator view stale rather than leaving a
		// job stuck, and stale is the recoverable half.
		if expired, err = (store.Leases{}).ExpireLeases(ctx, c, s.BatchLimit); err != nil {
			return err
		}

		if offline, err = (store.ScanPoints{}).MarkStaleOffline(ctx, c, s.now().Add(-HeartbeatTimeout)); err != nil {
			return err
		}

		// The escalation is written in the SAME transaction as the expiry.
		//
		// ADR-012 makes a non-reassign_safe lease loss an operator escalation,
		// and an escalation recorded afterwards is one that a crash can drop —
		// leaving a job marked 'failed' with 'lease_lost' and no record that
		// anybody was meant to look at it. The job state and the reason someone
		// should care about it commit together or not at all.
		for _, e := range expired {
			if e.ReassignSafe {
				continue
			}
			detail := map[string]any{
				"epoch":         e.Epoch,
				"reassign_safe": false,
				"requeued":      false,
				"reason":        "lease_lost",
			}
			if e.ScanPointID != nil {
				detail["scan_point_id"] = e.ScanPointID.String()
			}
			jobID := e.JobID
			if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorType:    store.ActorSystem,
				Action:       "job.lease_lost",
				ResourceType: "scan_job",
				ResourceID:   &jobID,
				Detail:       detail,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// ErrTenantNotResolved would mean the tenant went inactive between the
		// enumeration and the sweep, which is ordinary. Anything else is worth
		// seeing.
		if !errors.Is(err, store.ErrTenantNotResolved) {
			s.log.ErrorContext(ctx, "sweep: tenant pass", "tenant_id", tenant.String(), "error", err)
		}
		return
	}

	for _, e := range expired {
		// Two log levels on purpose. A requeued reassign_safe job is routine.
		// A non-reassign_safe job that lost its lease is work that stopped
		// halfway against a customer's estate and will not be retried — an
		// operator has to decide what happens next, so it does not get to look
		// like housekeeping in the log.
		attrs := []any{
			"tenant_id", tenant.String(),
			"job_id", e.JobID.String(),
			"epoch", e.Epoch,
			"reassign_safe", e.ReassignSafe,
			"requeued", e.Requeued,
		}
		if e.ScanPointID != nil {
			attrs = append(attrs, "scan_point_id", e.ScanPointID.String())
		}
		if e.ReassignSafe {
			s.log.InfoContext(ctx, "lease expired, job requeued", attrs...)
		} else {
			s.log.WarnContext(ctx, "lease expired on a job that must not retry; operator action required", attrs...)
		}
	}
	for _, id := range offline {
		s.log.InfoContext(ctx, "scan point missed the heartbeat timeout, marked offline",
			"tenant_id", tenant.String(), "scan_point_id", id.String(),
			"timeout", HeartbeatTimeout.String())
	}
}
