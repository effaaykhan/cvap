package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// ============================================================================
// F3 — the lease clock is the DB's, and a renewal cannot outrun expiry by
// reading a stale clock.
// ============================================================================
//
// Lease expiry is decided at the database with clock_timestamp() (real time when
// the statement runs), never now()/transaction_timestamp() (fixed at the
// transaction's start). The distinction is invisible until a renewal's
// transaction BEGINS before expiry but its UPDATE reaches the row only AFTER —
// which is exactly what a lock wait produces. now() would then evaluate the
// predicate against the transaction's start time, judge the lease live, and
// renew a lease that has in fact expired: two scan points on one job.
//
// This is the same class as the session-8 DST bug — a time assumption that
// agreed with itself on both sides of a boundary — and it is the scan-point
// clock-skew fault stated at its real seam. A scan point whose own clock lags
// still cannot renew out of lease, because the clock that decides is the DB's;
// this proves the DB refuses even the most favourable stale reading a caller
// could present.
//
// Forced by making the renewal's TRANSACTION begin before expiry while its
// fencing UPDATE runs after it: a statement early in the transaction fixes
// transaction_timestamp() before expiry, a wait carries real time past expiry,
// and only then does the renewal run. A lock wait is one way real deployments
// produce exactly this gap between transaction start and statement execution;
// the wait here stands in for it deterministically. now() reads the pre-expiry
// transaction start and renews; clock_timestamp() reads real time and refuses.
//
// The sabotage swaps clock_timestamp() for now() in the fencing predicate; under
// it, the renewal whose transaction began before expiry succeeds, and the
// assertion below fails. This binds because Renew runs in this test's process,
// where -overlay applies (contrast F2, whose decision runs only in a built
// binary).
//
// mutate:subject internal/store/leases.go
// mutate:test    ./internal/store/ -run TestExpiredLeaseCannotBeRenewedByATransactionThatBeganEarlier
//
// mutate:case    the fence reads transaction-start time, not real time
// mutate:old     		   AND expires_at > clock_timestamp()
// mutate:new     		   AND expires_at > now()
func TestExpiredLeaseCannotBeRenewedByATransactionThatBeganEarlier(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "f3-"+uuid.NewString()[:8])
	sp := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, sp, false)

	// A short TTL so a modest wait carries real time past expiry.
	const ttl = 800 * time.Millisecond
	var epoch int64
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		l, err := (store.Leases{}).Grant(ctx, c, jobID, sp, ttl)
		if err != nil {
			return err
		}
		epoch = l.Epoch
		return nil
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// One transaction: a first statement fixes transaction_timestamp() before
	// expiry, the sleep carries real time well past it, then the renewal runs.
	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var one int
		if err := c.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
			return err
		}
		time.Sleep(1500 * time.Millisecond) // past the 800ms TTL, by a margin
		_, err := (store.Leases{}).Renew(ctx, c, jobID, epoch, sp, 0)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("renewal returned %v, want ErrNotFound: a lease expired by the DB clock was "+
			"renewed by a transaction that began before expiry — the fence read a stale clock "+
			"(transaction-start time), and two scan points can now hold one job (ADR-012)", err)
	}
}
