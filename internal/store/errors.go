package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrNoTenantContext means an operation was attempted without a tenant.
	// Read and Write return it rather than defaulting to anything.
	ErrNoTenantContext = errors.New("store: no tenant context")

	// ErrTransactionEnded means the transaction a Conn was scoped to ended
	// before its callback did — almost always because the callback issued its
	// own COMMIT or ROLLBACK through Exec.
	//
	// This is a serious bug in the caller, not a transient failure. The tenant
	// context is carried by SET LOCAL, which Postgres discards when the
	// transaction ends, so everything after that point runs with whatever
	// session-level tenant is set — and a plain SET is then permanent for the
	// life of the connection. The store destroys such a connection rather than
	// returning it to the pool.
	//
	// Do not issue transaction-control statements through Conn. Read and Write
	// own the transaction.
	ErrTransactionEnded = errors.New("store: the transaction ended before its callback did")

	// ErrNotPermitted is a plain permission failure: a missing GRANT.
	//
	// Distinguished from ErrTenantIsolation because SQLSTATE 42501 covers both,
	// and they mean opposite things operationally. A cross-tenant write attempt
	// is a security event worth alerting on; a missing GRANT is a deployment
	// mistake. Alerting that cannot tell them apart fires on the wrong one and
	// gets muted.
	ErrNotPermitted = errors.New("store: permission denied")

	// ErrConnReleased means a *Conn was used after its callback returned. The
	// transaction is over and the underlying connection may already be serving
	// a different tenant, so this is a bug in the caller, not a transient
	// failure to retry.
	ErrConnReleased = errors.New("store: connection used after its callback returned")

	// ErrNotFound is the no-rows case, mapped off pgx so callers do not import
	// pgx to check it.
	//
	// Under RLS, "not found" and "exists but belongs to another tenant" are the
	// same answer by design. Do not add an error that distinguishes them.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is a unique-constraint violation: the row already exists.
	ErrConflict = errors.New("store: conflict")

	// ErrForeignKey is a foreign-key violation. On this schema it very often
	// means a composite (tenant_id, parent_id) FK refused a cross-tenant
	// parent (ADR-017), which is the constraint working, not a fault.
	ErrForeignKey = errors.New("store: foreign key violation")

	// ErrCheckViolation is a CHECK constraint refusing the row.
	ErrCheckViolation = errors.New("store: check constraint violation")

	// ErrTenantIsolation means RLS refused the operation — most often a write
	// whose tenant_id did not match the connection's tenant, caught by the
	// WITH CHECK half of the policy.
	ErrTenantIsolation = errors.New("store: row-level security refused the operation")

	// ErrStatementTimeout means the transaction exceeded its budget and the
	// database (or the deadline) stopped it (ADR-101, B50).
	//
	// It is NOT a fault in the caller's request and it is NOT a bug: it is the
	// bound doing its job. What it always means is that some statement reached a
	// plan nobody measured, so a timeout is a signal to profile, not to retry —
	// a retry runs the same plan and spends the budget again.
	//
	// Read what it does NOT promise. A transaction that hits this rolled back,
	// and it took everything written before it in the same transaction with it.
	// A refusal audit event recorded in the transaction that then times out is
	// discarded, exactly as a refusal that returns an error from inside the
	// closure is (see rollback-discards-the-control, three instances). If a
	// write must leave a record of WHY it refused, that record does not belong
	// in the transaction whose fate is in question.
	ErrStatementTimeout = errors.New("store: statement exceeded its time budget")

	// ErrTenantNotResolved means a scan point certificate fingerprint did not
	// resolve to a tenant (ADR-031).
	//
	// Deliberately identical for "no such fingerprint" and "revoked or disabled
	// scan point". Distinguishing them would make this an oracle for whether a
	// fingerprint is enrolled, which is what the SQL function avoids by
	// returning NULL rather than raising.
	ErrTenantNotResolved = errors.New("store: certificate fingerprint did not resolve to a tenant")
)

// PostgreSQL error codes, spelled out rather than inlined as magic strings.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCheckViolation      = "23514"
	pgNotNullViolation    = "23502"
	pgInsufficientPriv    = "42501" // RLS refusal arrives as this
	pgUndefinedObject     = "42704" // unset app.tenant_id, from one-arg current_setting
	pgInvalidTextRepr     = "22P02" // app.tenant_id set to something that is not a uuid
	pgQueryCanceled       = "57014" // statement_timeout, AND a client-side cancel
)

// mapError converts a pgx or pgconn error into this package's sentinels.
//
// Constraint names are preserved in the wrapped message because on this schema
// they are diagnostic: findings_dedup_key_uidx and network_ranges_zone_fk say
// very different things about what the caller did wrong.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// The request-level half of the budget (ADR-101). The transaction ran
		// past its deadline and pgx cancelled it. Wrapped rather than replaced,
		// so a caller that cares which bound fired can still ask.
		return fmt.Errorf("%w: %w", ErrStatementTimeout, err)
	}
	if errors.Is(err, context.Canceled) {
		// The caller went away. Not our bound, and not a 504: nobody is waiting
		// for the answer.
		return err
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}

	switch pgErr.Code {
	case pgUniqueViolation:
		return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
	case pgForeignKeyViolation:
		return fmt.Errorf("%w: %s", ErrForeignKey, pgErr.ConstraintName)
	case pgCheckViolation:
		return fmt.Errorf("%w: %s", ErrCheckViolation, pgErr.ConstraintName)
	case pgNotNullViolation:
		return fmt.Errorf("store: %s is NOT NULL: %w", pgErr.ColumnName, err)
	case pgInsufficientPriv:
		// 42501 is both "new row violates row-level security policy" and
		// "permission denied for table". Discriminate on the message: they mean
		// opposite things to whoever handles them.
		if strings.HasPrefix(pgErr.Message, "new row violates row-level security policy") {
			return fmt.Errorf("%w: %s", ErrTenantIsolation, pgErr.Message)
		}
		return fmt.Errorf("%w: %s", ErrNotPermitted, pgErr.Message)
	case pgUndefinedObject:
		// A policy evaluated current_setting('app.tenant_id') with nothing set.
		// Reaching this means a query ran outside Read/Write, which should not
		// be possible from this package.
		return fmt.Errorf("%w: query ran without a usable app.tenant_id (%s)",
			ErrNoTenantContext, pgErr.Message)
	case pgQueryCanceled:
		// 57014 is BOTH "canceling statement due to statement timeout" and
		// "canceling statement due to user request" (a client-side cancel,
		// which is what pgx issues when a context is cancelled). They mean
		// opposite things: the first is our bound firing and belongs in a 504,
		// the second is the caller having left. Discriminate on the message,
		// the same way 42501 is split above.
		if strings.Contains(pgErr.Message, "statement timeout") {
			return fmt.Errorf("%w: %s", ErrStatementTimeout, pgErr.Message)
		}
		return err
	case pgInvalidTextRepr:
		// 22P02 is ANY bad text-to-type cast, not only a bad app.tenant_id. It
		// was mapped to ErrNoTenantContext, so a scan point sending a malformed
		// jsonb payload made Core log "query ran without a usable app.tenant_id"
		// — an attacker-triggerable, alarming and wrong message. Only claim the
		// tenant-context reading when the message actually names the setting.
		if strings.Contains(pgErr.Message, "app.tenant_id") {
			return fmt.Errorf("%w: query ran without a usable app.tenant_id (%s)",
				ErrNoTenantContext, pgErr.Message)
		}
		return fmt.Errorf("%w: %s", ErrCheckViolation, pgErr.Message)
	}
	return err
}

// errRow lets QueryRow report a released connection through Scan, matching how
// pgx surfaces errors from QueryRow.
type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

// errBatchResults lets SendBatch report a released connection without a nil
// dereference at the call site.
type errBatchResults struct{ err error }

func (b errBatchResults) Exec() (pgconn.CommandTag, error) { return pgconn.CommandTag{}, b.err }
func (b errBatchResults) Query() (Rows, error)             { return nil, b.err }
func (b errBatchResults) QueryRow() Row                    { return errRow(b) }
func (b errBatchResults) Close() error                     { return b.err }
