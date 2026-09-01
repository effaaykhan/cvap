// Package store is the PostgreSQL access layer.
//
// Every query runs under a tenant context so that row-level security applies:
// a forgotten predicate must produce an empty result, never another tenant's
// rows (ADR-002, ADR-017). Application roles never bypass RLS; only migrations
// do.
//
// The tenant context is set with SET LOCAL inside a transaction, so Postgres
// discards it at COMMIT or ROLLBACK and a pooled connection cannot carry the
// previous request's tenant. Read and Write are the only ways to obtain a
// queryable connection, and a TenantID is what opens them.
//
// See CLAUDE.md in this directory for the rest, and encapsulation_test.go for
// the properties that are enforced rather than described.
package store
