package store

import "github.com/jackc/pgx/v5"

// Batch is a set of statements sent in one round trip.
//
// It exists because *pgx.Batch cannot be accepted from a caller. pgx.Batch.Queue
// returns a *pgx.QueuedQuery, which has Query(fn func(pgx.Rows) error) — pgx
// stores that function and calls it later with a live pgx.Rows, and pgx.Rows
// carries Conn() *pgx.Conn. So a caller-supplied batch is a caller-supplied
// callback, and a caller-supplied callback is handed the pooled connection.
// It then outlives the transaction, has no tenant, and accepts
// SET app.tenant_id = anything.
//
// That is the same leak rows.go closes on the return side, arriving through a
// parameter instead. The general rule, which is worth more than either fix:
//
//	A parameter type that carries a caller-supplied function is as dangerous as
//	a return type that exposes a connection. Both hand out whatever the library
//	decides to pass that function.
//
// Queue DISCARDS the *pgx.QueuedQuery. That discard is the whole fix — with no
// handle, no callback can be attached.
type Batch struct {
	b pgx.Batch
}

// Queue adds a statement. The pgx handle is deliberately not returned.
func (b *Batch) Queue(sql string, args ...any) {
	_ = b.b.Queue(sql, args...)
}

// Len is the number of queued statements.
func (b *Batch) Len() int { return b.b.Len() }
