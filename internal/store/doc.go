// Package store is the PostgreSQL access layer.
//
// Every query runs under a tenant context so that row-level security applies:
// a forgotten predicate must produce an empty result, never another tenant's
// rows (ADR-002, ADR-017). Application roles never bypass RLS; only migrations
// do.
package store
