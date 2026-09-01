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
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
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
	case pgUndefinedObject, pgInvalidTextRepr:
		// A policy evaluated current_setting('app.tenant_id') with nothing set,
		// or with something that is not a uuid. Reaching this means a query ran
		// outside Read/Write, which should not be possible from this package —
		// so it is worth an error that says so rather than a bare pg code.
		return fmt.Errorf("%w: query ran without a usable app.tenant_id (%s)",
			ErrNoTenantContext, pgErr.Message)
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
func (b errBatchResults) QueryRow() Row                    { return errRow{b.err} }
func (b errBatchResults) Close() error                     { return b.err }
