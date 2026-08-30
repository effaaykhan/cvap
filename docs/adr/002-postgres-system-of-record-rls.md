# ADR-002: PostgreSQL as system of record; RLS enforces tenancy

**Status:** Accepted
**Date:** 2026-08-30

## Context

The platform is multi-tenant from day one and holds a complete map of each customer's
exploitable weaknesses. A single forgotten `WHERE tenant_id = ...` in any query path is a
cross-tenant disclosure of exactly the data an attacker would most want. Tenant isolation
cannot depend on every developer remembering it in every query.

## Decision

PostgreSQL 16 is the system of record for all structured state. Every tenant-scoped table
carries `tenant_id` and has a row-level security policy of the form
`tenant_id = current_setting('app.tenant_id')::uuid`, created in the same migration that
creates the table. Application roles cannot bypass RLS; only migration roles do. A forgotten
predicate therefore produces an empty result set, not a leak.

## Alternatives considered

**Discipline plus code review.** The historical failure mode of every multi-tenant system.
It works until the first hotfix at 2am, and the failure is silent and unbounded.

**A database-per-tenant.** Genuinely strong isolation, but it makes cross-tenant knowledge
data, schema migrations and SaaS operations expensive, and it does not match the on-prem
deployment where there is exactly one tenant. It also conflicts with ADR-017's
single-codebase commitment.

**An application-layer query builder that injects the tenant predicate.** Better than
discipline, but it is our own code enforcing our own invariant — the same trust boundary
that failed. Raw SQL, reporting queries and migrations all route around it. RLS is enforced
by the database beneath every access path.

**A non-relational store for scale.** Observations are the growth vector, and partitioning
(ADR-016) handles that. Everything else — identity resolution, dedup, correlation, risk —
is relational work that Postgres does far past the point we expect to need it, and it gives
transactional job state for free (ADR-003).

## Consequences

Tenant isolation becomes a schema property that a migration audit can verify mechanically,
which is why `schema-auditor` exists. Every connection must set `app.tenant_id` before use,
so connection pooling and background workers need explicit tenant context. Migrations
acquire a standing obligation: a new tenant-scoped table without an RLS policy in the same
migration is a defect, not a follow-up.

## Review trigger

Revisit if a measured workload — most likely observation ingest — exceeds what a single
primary with read replicas can serve, or if RLS policy evaluation shows up as a material
cost in query plans on the hot ingest path.
