package store

import (
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Why this file exists.
//
// pgx.Rows carries a Conn() *pgx.Conn method. So does anything reached through
// pgx.BatchResults, whose Query() returns a pgx.Rows. Returning either of those
// types from Conn.Query or Conn.SendBatch would therefore hand a caller the raw
// connection through an interface method nobody wrote and nobody would notice —
// and a *pgx.Conn retained past the callback outlives the transaction that
// scoped it to a tenant, which is precisely the leak the package is built to
// prevent.
//
// It is a subtle hole: the signature says pgx.Rows, which looks like a result
// set. The reachability is one method call away and invisible at the call site.
//
// So Conn returns these narrowed interfaces instead. They carry everything a
// caller needs to read a result and nothing that leads back to a connection.
// The wrappers hold the pgx value as a NAMED field rather than embedding it,
// for the same reason Conn holds pgx.Tx that way: embedding promotes Conn().
//
// encapsulation_test.go lists pgx.Rows and pgx.BatchResults as forbidden in the
// exported API so a future signature cannot quietly widen back.

// Rows is a result set with no route back to the connection.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Values() ([]any, error)
	RawValues() [][]byte
	FieldDescriptions() []pgconn.FieldDescription
	CommandTag() pgconn.CommandTag
	Err() error
	Close()
}

// Row is a single-row result. pgx.Row already exposes only Scan, so this exists
// for symmetry and so error mapping can be applied on the way through.
type Row interface {
	Scan(dest ...any) error
}

// BatchResults is a batch result set with no route back to the connection.
type BatchResults interface {
	Exec() (pgconn.CommandTag, error)
	Query() (Rows, error)
	QueryRow() Row
	Close() error
}

type rows struct{ r pgx.Rows }

func (w rows) Next() bool                                   { return w.r.Next() }
func (w rows) Scan(dest ...any) error                       { return mapError(w.r.Scan(dest...)) }
func (w rows) Values() ([]any, error)                       { v, err := w.r.Values(); return v, mapError(err) }
func (w rows) RawValues() [][]byte                          { return w.r.RawValues() }
func (w rows) FieldDescriptions() []pgconn.FieldDescription { return w.r.FieldDescriptions() }
func (w rows) CommandTag() pgconn.CommandTag                { return w.r.CommandTag() }
func (w rows) Err() error                                   { return mapError(w.r.Err()) }
func (w rows) Close()                                       { w.r.Close() }

type row struct{ r pgx.Row }

func (w row) Scan(dest ...any) error { return mapError(w.r.Scan(dest...)) }

type batchResults struct{ b pgx.BatchResults }

func (w batchResults) Exec() (pgconn.CommandTag, error) {
	tag, err := w.b.Exec()
	return tag, mapError(err)
}

func (w batchResults) Query() (Rows, error) {
	r, err := w.b.Query()
	if err != nil {
		return nil, mapError(err)
	}
	return rows{r}, nil
}

func (w batchResults) QueryRow() Row { return row{w.b.QueryRow()} }

func (w batchResults) Close() error { return mapError(w.b.Close()) }
