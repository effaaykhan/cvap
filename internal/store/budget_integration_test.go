package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// The transaction budget (ADR-101, B50).
//
// B50 is not "the finding list is slow" — that is B48. B50 is that no operator
// read carried a bound at all, so a plan nobody measured ran for 91 minutes and
// nothing stopped it. These tests are about the BOUND, and every one of them
// asserts a property that was false before it existed.

// A single runaway statement is stopped, and stopped by the database.
func TestABudgetStopsARunawayStatement(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "budget-runaway")

	start := time.Now()
	err := db.ReadWithin(context.Background(), tenant, 400*time.Millisecond,
		func(ctx context.Context, c *store.Conn) error {
			_, err := c.Exec(ctx, "SELECT pg_sleep(10)")
			return err
		})
	elapsed := time.Since(start)

	if !errors.Is(err, store.ErrStatementTimeout) {
		t.Fatalf("want ErrStatementTimeout, got %v", err)
	}
	// The bound is worthless if it merely renames the wait. Ten seconds of
	// sleep must not have been slept.
	if elapsed > 5*time.Second {
		t.Fatalf("budget did not bound the wait: took %s", elapsed)
	}
}

// The property the whole design turns on, and the one a statement_timeout alone
// does NOT give.
//
// Measured before this test was written: three pg_sleep(0.8) statements inside
// one transaction with statement_timeout = 1s all completed, 2.4 s in total,
// none cancelled. statement_timeout is reset for EVERY statement, so a callback
// issuing many short statements runs unbounded while never tripping it — a
// bound stated over the request and enforced over the statement.
//
// Six 400 ms sleeps are 2.4 s of work in statements that are each comfortably
// inside a 1 s budget. If the only bound were statement_timeout, every one of
// them would succeed and this transaction would commit.
func TestTheBudgetBoundsTheTransactionNotOnlyTheStatement(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "budget-whole-tx")

	start := time.Now()
	err := db.ReadWithin(context.Background(), tenant, 1*time.Second,
		func(ctx context.Context, c *store.Conn) error {
			for i := 0; i < 6; i++ {
				if _, err := c.Exec(ctx, "SELECT pg_sleep(0.4)"); err != nil {
					return err
				}
			}
			return nil
		})
	elapsed := time.Since(start)

	if !errors.Is(err, store.ErrStatementTimeout) {
		t.Fatalf("six short statements ran to completion inside a 1s budget: %v "+
			"(this is the statement-vs-transaction gap; the context deadline is what closes it)", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("transaction was not bounded: took %s", elapsed)
	}
}

// What a timeout does to a WRITE, and specifically to a refusal that recorded
// itself.
//
// internal/store/CLAUDE.md prescribes the shape this test uses: a closure that
// refuses returns NIL and carries the refusal out in a variable, so the record
// of the refusal commits. Three shipped defects came from getting that wrong.
//
// The budget introduces a fourth way for the record to be lost, and it is NOT
// fixed by that shape: if the transaction times out, everything in it rolls
// back, including the audit event. The refusal still happened — `denied` is
// set — but nothing durable says so.
//
// This test exists to pin that consequence rather than to describe it. It is
// why the handlers check the transaction error BEFORE the refusal variable: a
// refusal that was not recorded must not be reported as though it was.
func TestABudgetTimeoutDiscardsARefusalRecordedInTheSameTransaction(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "budget-refusal")

	actor := uuid.New()
	resource := uuid.New()
	errRefused := errors.New("refused")

	var denied error
	err := db.WriteWithin(context.Background(), tenant, 700*time.Millisecond,
		func(ctx context.Context, c *store.Conn) error {
			denied = errRefused
			if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorID: &actor, ActorType: store.ActorUser,
				Action: "test.refused", ResourceType: "user", ResourceID: &resource,
			}); err != nil {
				return err
			}
			// Whatever the transaction goes on to do, it runs out of budget.
			_, err := c.Exec(ctx, "SELECT pg_sleep(10)")
			return err
		})

	if !errors.Is(err, store.ErrStatementTimeout) {
		t.Fatalf("want ErrStatementTimeout, got %v", err)
	}
	if denied == nil {
		t.Fatal("the closure decided a refusal; the variable should still hold it")
	}

	// The record is gone. Read in a FRESH transaction, because the one above no
	// longer exists.
	var events []store.AuditEvent
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		events, err = (store.AuditEvents{}).ListByResource(ctx, c, "user", resource, 10)
		return err
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected the refusal record to have been rolled back with the "+
			"transaction, found %d event(s): the premise of ADR-101's write section is wrong", len(events))
	}
}

// A committed refusal is still a committed refusal. The control above must not
// pass by making every write fail.
func TestARefusalRecordedWithinBudgetSurvives(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "budget-refusal-ok")

	actor := uuid.New()
	resource := uuid.New()

	if err := db.WriteWithin(context.Background(), tenant, 10*time.Second,
		func(ctx context.Context, c *store.Conn) error {
			return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorID: &actor, ActorType: store.ActorUser,
				Action: "test.refused", ResourceType: "user", ResourceID: &resource,
			})
		}); err != nil {
		t.Fatalf("write: %v", err)
	}

	var events []store.AuditEvent
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		events, err = (store.AuditEvents{}).ListByResource(ctx, c, "user", resource, 10)
		return err
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want the refusal recorded, got %d events", len(events))
	}
}

// Unbounded is the state B50 records. It must not be reachable by passing zero.
func TestABudgetMustBePositive(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "budget-zero")

	for _, d := range []time.Duration{0, -time.Second} {
		err := db.ReadWithin(context.Background(), tenant, d,
			func(ctx context.Context, c *store.Conn) error { return nil })
		if err == nil {
			t.Fatalf("budget %s was accepted; unbounded must not be reachable", d)
		}
	}
}

// The default doors carry the bound too. A caller that never heard of
// ReadWithin still gets one, which is the difference between a bound and an
// option.
func TestReadAndWriteCarryTheOperatorBudget(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "budget-default")

	for _, tc := range []struct {
		name string
		run  func(func(context.Context, *store.Conn) error) error
	}{
		{"Read", func(fn func(context.Context, *store.Conn) error) error {
			return db.Read(context.Background(), tenant, fn)
		}},
		{"Write", func(fn func(context.Context, *store.Conn) error) error {
			return db.Write(context.Background(), tenant, fn)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var applied string
			if err := tc.run(func(ctx context.Context, c *store.Conn) error {
				return c.QueryRow(ctx, "SELECT current_setting('statement_timeout')").Scan(&applied)
			}); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if applied != "30s" {
				t.Fatalf("%s ran with statement_timeout=%q, want the operator budget 30s", tc.name, applied)
			}
		})
	}
}
