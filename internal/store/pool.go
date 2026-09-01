package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The tenant context problem, and why this file looks the way it does.
//
// Forty RLS policies protect this schema, and there is exactly one failure they
// cannot help with: a pooled connection that still carries the previous
// request's tenant. The policy then evaluates perfectly against the wrong
// tenant, and every row it returns is a cross-tenant disclosure that looks
// entirely correct in the logs. RLS defends against a forgotten predicate. It
// has nothing to say about a correct predicate with the wrong value.
//
// Three properties, together, make that unrepresentable rather than merely
// unlikely.
//
//  1. SET LOCAL, inside a transaction, always. A session-level SET must be
//     undone by our own cleanup code on release — and cleanup that must run is
//     cleanup that eventually does not: a panic, a cancelled context mid-release,
//     a new code path whose author did not know. SET LOCAL is discarded by
//     Postgres when the transaction ends. The database does the clearing; we
//     cannot forget it. This is why there is no non-transactional path here, and
//     why adding one would undo the guarantee.
//
//     Note the precise form of that claim, because a looser reading of it was
//     wrong. Postgres discards the setting when THE TRANSACTION ends — not
//     necessarily when this function decides it ends. Conn.Exec takes arbitrary
//     SQL, and COMMIT is arbitrary SQL: a callback that commits its own
//     transaction discards the SET LOCAL and can then issue a plain SET that
//     sticks for the life of the connection. pgxpool would recycle that
//     connection happily, since it destroys only connections whose TxStatus is
//     not 'I' and a self-issued COMMIT leaves exactly 'I'.
//
//     So the store has to know whether the transaction it opened is the one
//     that ended. inTx acquires the connection itself, checks TxStatus (a
//     cached byte, no round trip) after the callback and after commit, and
//     closes the underlying connection — making the pool destroy rather than
//     recycle it — whenever the state is not the one it established. check()
//     refuses further operations on the same basis.
//
//  2. The connection cannot be reached. Conn holds an unexported pgx.Tx, and
//     does NOT embed it — embedding would promote Tx.Conn() and hand out the
//     raw connection through a method nobody wrote. DB holds the pool the same
//     way. Nothing exported in this package returns *pgx.Conn, *pgxpool.Conn or
//     *pgxpool.Pool, and encapsulation_test.go fails the build if that changes.
//
//  3. The only doors are Read and Write, both callback-scoped, both requiring a
//     TenantID to open. There is no Acquire, no Begin, no escape hatch — a
//     caller cannot obtain a connection and then decide about tenancy, because
//     the tenant is what opens the door.
//
// Rejected: carrying the tenant in context.Context, which is the idiomatic Go
// answer. It is "discouraged, not impossible" — a caller can build a background
// context, lose the tenant, and nothing fails until it is a customer's data.

// TenantID is the tenant a connection is scoped to.
//
// A distinct type rather than a bare uuid.UUID or string, so that a tenant id
// cannot be passed where an asset id was meant. The zero value is deliberately
// invalid: a TenantID{} names no tenant and is rejected by Read and Write
// rather than being treated as "unset" and quietly widened.
type TenantID struct {
	u uuid.UUID
}

// NewTenantID converts a uuid into a TenantID. It rejects the nil uuid, which
// is what a zero-valued struct field or a failed parse looks like.
func NewTenantID(u uuid.UUID) (TenantID, error) {
	if u == uuid.Nil {
		return TenantID{}, ErrNoTenantContext
	}
	return TenantID{u: u}, nil
}

// ParseTenantID converts the string form, as it arrives from an API request or
// a JWT claim.
func ParseTenantID(s string) (TenantID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return TenantID{}, fmt.Errorf("parse tenant id: %w", err)
	}
	return NewTenantID(u)
}

// UUID returns the underlying uuid. Reading it is safe; it is only the
// unchecked construction of a TenantID that this package withholds.
func (t TenantID) UUID() uuid.UUID { return t.u }

func (t TenantID) String() string { return t.u.String() }

// IsZero reports whether this TenantID names no tenant.
func (t TenantID) IsZero() bool { return t.u == uuid.Nil }

// Config is what Open needs. Everything except URL has a working default.
type Config struct {
	// URL is a libpq connection string. It must authenticate as a role that
	// holds neither BYPASSRLS nor SUPERUSER — Open verifies this rather than
	// trusting deployment to have got it right, because a role with BYPASSRLS
	// makes every policy in the schema decorative and nothing else would fail.
	URL string

	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxConns == 0 {
		c.MaxConns = 16
	}
	if c.MinConns == 0 {
		c.MinConns = 2
	}
	if c.MaxConnLifetime == 0 {
		c.MaxConnLifetime = time.Hour
	}
	if c.MaxConnIdleTime == 0 {
		c.MaxConnIdleTime = 30 * time.Minute
	}
	if c.HealthCheckPeriod == 0 {
		c.HealthCheckPeriod = time.Minute
	}
	return c
}

// DB is a tenant-aware connection pool.
//
// The pool field is unexported and has no accessor. That is the point: see the
// note at the top of this file.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects, verifies the connecting role cannot bypass RLS, and returns a
// pool. It does not return anything from which a raw connection can be reached.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	cfg = cfg.withDefaults()
	if cfg.URL == "" {
		return nil, errors.New("store: Config.URL is empty")
	}

	pcfg, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("store: parse connection string: %w", err)
	}
	pcfg.MaxConns = cfg.MaxConns
	pcfg.MinConns = cfg.MinConns
	pcfg.MaxConnLifetime = cfg.MaxConnLifetime
	pcfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	pcfg.HealthCheckPeriod = cfg.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}

	db := &DB{pool: pool}
	if err := db.verifyRole(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// verifyRole refuses to hand back a pool whose role can bypass RLS.
//
// Migration 0001 asserts this at deploy time; this asserts it at connect time,
// because the two catch different things. The migration catches a cluster
// provisioned wrong. This catches an application pointed at the wrong role
// afterwards — a DATABASE_URL edited to use the migration user to "fix" a
// permission error being the obvious case, and one that would otherwise work
// perfectly while silently disabling tenant isolation.
func (db *DB) verifyRole(ctx context.Context) error {
	var role string
	var bypassRLS, super bool
	err := db.pool.QueryRow(ctx,
		`SELECT current_user, rolbypassrls, rolsuper
		   FROM pg_roles WHERE rolname = current_user`,
	).Scan(&role, &bypassRLS, &super)
	if err != nil {
		return fmt.Errorf("store: verify connecting role: %w", err)
	}
	if bypassRLS || super {
		return fmt.Errorf(
			"store: connecting role %q holds BYPASSRLS or SUPERUSER; every RLS policy in the schema would be inert (ADR-002). Connect as the application role",
			role)
	}
	return nil
}

func (db *DB) Close() { db.pool.Close() }

// Ping checks the pool can reach the database.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// Conn is the only query surface this package offers.
//
// It cannot be built outside this package — every field is unexported and there
// is no exported constructor — and it cannot be unwrapped, because tx is a
// named field rather than an embedded one. Embedding pgx.Tx would promote its
// Conn() method and hand out the raw connection.
//
// A Conn is valid only for the duration of the callback it was passed to. After
// that callback returns, the transaction is finished and the connection belongs
// to whoever acquires it next, quite possibly under a different tenant — so
// every method checks done first and returns ErrConnReleased rather than
// running a query against a connection that is no longer ours.
type Conn struct {
	// pc is held so check() can read the connection's transaction status. It is
	// never handed out; pgxpool.Conn.Conn() and .Hijack() both return the raw
	// connection, which is exactly what this package exists to withhold.
	pc     *pgxpool.Conn
	tx     pgx.Tx
	tenant TenantID

	// atomic because a callback may start a goroutine, and the invalidating
	// write happens in a deferred function with no happens-before edge to a
	// read from that goroutine. A *Conn is single-goroutine by contract — pgx
	// connections are not goroutine-safe — but "this is a bug anyway" is not a
	// reason to make the detection itself racy.
	done atomic.Bool
}

// Tenant is the tenant this connection is scoped to.
//
// Repositories take the tenant from here rather than as a separate argument.
// That removes an entire class of bug: a caller cannot open the connection as
// tenant A and write a row claiming tenant B, because there is only one tenant
// in play and it is the one the database is enforcing.
func (c *Conn) Tenant() TenantID { return c.tenant }

// check guards every operation.
//
// The second half is the important one, and it exists because Conn.Exec takes
// arbitrary SQL by design — and COMMIT is arbitrary SQL. A callback that issues
// its own COMMIT ends the transaction that carried the SET LOCAL, and then a
// plain `SET app.tenant_id = ...` sticks at session level. Everything after
// that in the callback runs as whatever tenant it named, and the connection
// goes back to the pool still carrying it: pgxpool only destroys a connection
// whose TxStatus is not 'I', and after a self-issued COMMIT it is exactly 'I'.
//
// TxStatus is a cached byte from the last ReadyForQuery, so checking it costs
// no round trip.
//
// 'T' means in a transaction block, which is where we should be. 'E' means the
// transaction is aborted after an error — normal, and left to pgx to report so
// the caller sees the real error rather than this one. 'I' means there is no
// transaction at all, which after inTx opened one can only mean the callback
// ended it.
func (c *Conn) check() error {
	if c == nil || c.done.Load() {
		return ErrConnReleased
	}
	if c.pc.Conn().PgConn().TxStatus() == 'I' {
		c.done.Store(true)
		return ErrTransactionEnded
	}
	return nil
}

// Exec runs a statement. Errors are mapped to this package's sentinels here,
// at the boundary, so a caller writing its own SQL through Conn gets the same
// error values a repository method would return. An RLS refusal arriving as a
// bare SQLSTATE 42501 from one path and as ErrTenantIsolation from another is
// the kind of inconsistency that gets handled in only one of the two.
func (c *Conn) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := c.check(); err != nil {
		return pgconn.CommandTag{}, err
	}
	tag, err := c.tx.Exec(ctx, sql, args...)
	return tag, mapError(err)
}

// Query returns store.Rows, NOT pgx.Rows. pgx.Rows carries Conn() *pgx.Conn,
// so returning it would hand out the raw connection through an interface method
// — see rows.go.
func (c *Conn) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	r, err := c.tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, mapError(err)
	}
	return rows{r}, nil
}

// QueryRow follows pgx: errors surface from Scan rather than here. A released
// Conn returns a Row whose Scan reports ErrConnReleased.
func (c *Conn) QueryRow(ctx context.Context, sql string, args ...any) Row {
	if err := c.check(); err != nil {
		return errRow{err}
	}
	return row{c.tx.QueryRow(ctx, sql, args...)}
}

// SendBatch runs a pgx batch. Used by the observation write path, where the
// ingest target is thousands of rows per second and a round trip per row is not
// affordable.
//
// Returns store.BatchResults for the same reason Query returns store.Rows: the
// pgx type's Query() hands back a pgx.Rows, and that leads to the connection.
func (c *Conn) SendBatch(ctx context.Context, b *Batch) BatchResults {
	if err := c.check(); err != nil {
		return errBatchResults{err}
	}
	if b == nil {
		return errBatchResults{errors.New("store: nil batch")}
	}
	return batchResults{c.tx.SendBatch(ctx, &b.b)}
}

// Read runs fn inside a READ ONLY transaction scoped to tenant.
//
// Read-only is not decoration: it means an INSERT that finds its way onto a read
// path fails at the database rather than in review. Use Write when the operation
// is meant to write.
func (db *DB) Read(ctx context.Context, tenant TenantID, fn func(context.Context, *Conn) error) error {
	return db.inTx(ctx, tenant, pgx.TxOptions{AccessMode: pgx.ReadOnly}, fn)
}

// Write runs fn inside a read-write transaction scoped to tenant.
func (db *DB) Write(ctx context.Context, tenant TenantID, fn func(context.Context, *Conn) error) error {
	return db.inTx(ctx, tenant, pgx.TxOptions{}, fn)
}

func (db *DB) inTx(ctx context.Context, tenant TenantID, opts pgx.TxOptions, fn func(context.Context, *Conn) error) error {
	if tenant.IsZero() {
		return ErrNoTenantContext
	}
	if fn == nil {
		return errors.New("store: nil callback")
	}

	// Acquire explicitly rather than using db.pool.BeginTx, because the store
	// has to decide whether this connection is fit to go back in the pool. The
	// pool's own rule — destroy unless TxStatus is 'I' — is not enough: a
	// callback that issues its own COMMIT leaves the status at 'I' with a
	// session-level tenant still set, which is precisely the state that must
	// never be recycled.
	pconn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire: %w", err)
	}

	// destroy is armed whenever the connection's transaction state is not what
	// this function established. Closing the underlying connection makes
	// Release destroy it instead of recycling it, which takes any session state
	// with it.
	destroy := false
	defer func() {
		if destroy {
			_ = pconn.Conn().Close(ctx)
		}
		pconn.Release()
	}()

	tx, err := pconn.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}

	// Rollback on every path that is not an explicit commit, including a panic.
	// Rolling back an already-committed transaction is a no-op in pgx, so this
	// is safe to arm unconditionally — and arming it unconditionally is what
	// makes it correct under panic.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	// set_config with is_local = true, which is SET LOCAL by another name.
	//
	// SET LOCAL itself takes no bind parameters, so using it would mean
	// interpolating a value into SQL — an injection shape in the one statement
	// that decides which tenant's data this connection can see. set_config
	// takes the tenant as a parameter.
	//
	// It also returns what it set, so the value is verified on the same round
	// trip rather than trusted. A GUC that silently failed to take would leave
	// the transaction running with no tenant context, where the one-argument
	// current_setting in every policy raises — safe, but confusing. Better to
	// fail here, saying why.
	var applied string
	if err := tx.QueryRow(ctx,
		`SELECT set_config('app.tenant_id', $1, true)`, tenant.String(),
	).Scan(&applied); err != nil {
		return fmt.Errorf("store: set tenant context: %w", err)
	}
	if applied != tenant.String() {
		return fmt.Errorf("store: tenant context did not take: set %q, got %q", tenant, applied)
	}

	c := &Conn{pc: pconn, tx: tx, tenant: tenant}
	// Invalidate on the way out, whatever happens, so a *Conn captured by the
	// callback and used later fails loudly instead of running against a
	// connection that now belongs to a different tenant.
	defer func() { c.done.Store(true) }()

	fnErr := fn(ctx, c)

	// Did the callback end the transaction we opened? 'T' is in-transaction and
	// 'E' is an aborted transaction still awaiting rollback; both are ours to
	// finish. Anything else means the transaction ended underneath us, so the
	// connection may carry session state and must not be recycled.
	if status := pconn.Conn().PgConn().TxStatus(); status != 'T' && status != 'E' {
		destroy = true
		committed = true // there is nothing left to roll back
		if fnErr != nil {
			return fnErr
		}
		return fmt.Errorf("%w: transaction status %q after the callback returned",
			ErrTransactionEnded, string(status))
	}

	if fnErr != nil {
		return fnErr
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true

	// After a clean commit the connection must be idle. Anything else means it
	// is in a state this function did not create, so it does not go back.
	if status := pconn.Conn().PgConn().TxStatus(); status != 'I' {
		destroy = true
		return fmt.Errorf("%w: transaction status %q after commit",
			ErrTransactionEnded, string(status))
	}
	return nil
}

// resolveTenant maps a scan point certificate fingerprint to its tenant, for
// enrolment — the one operation that must run before any tenant is known
// (ADR-031).
//
// Unexported on purpose, and it returns a TenantID and nothing else. It must
// never return a *Conn: the whole design above is that no code path obtains a
// connection without a tenant, and an enrolment path handing back a live
// connection would reopen exactly that. Callers resolve the tenant, then enter
// Write(ctx, tenant, ...) like everything else.
//
// The narrowness lives in the database, not here: tenant_for_scan_point is
// SECURITY DEFINER, returns one uuid, resolves only enrollable statuses, and
// returns NULL rather than raising on no match so it is not an enrolment oracle.
// This function is a thin call through to it and must stay that way.
func (db *DB) resolveTenant(ctx context.Context, certFingerprint string) (TenantID, error) {
	if certFingerprint == "" {
		return TenantID{}, ErrTenantNotResolved
	}

	var u *uuid.UUID
	err := db.pool.QueryRow(ctx,
		`SELECT tenant_for_scan_point($1)`, certFingerprint,
	).Scan(&u)
	if err != nil {
		return TenantID{}, fmt.Errorf("store: resolve tenant for scan point: %w", err)
	}
	if u == nil {
		// No match, or a revoked or disabled scan point. Deliberately the same
		// error for both: the caller must not be able to tell them apart, or it
		// becomes the oracle the SQL function avoids being.
		return TenantID{}, ErrTenantNotResolved
	}
	return NewTenantID(*u)
}
