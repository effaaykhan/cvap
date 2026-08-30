# ADR-017: Tenant-aware always, single-tenant by configuration

**Status:** Accepted
**Date:** 2026-08-30

## Context

Both SaaS and on-prem are targets from the start. The usual outcome of pursuing both is two
products: a multi-tenant codebase and a stripped single-tenant fork that drift apart until
every feature must be built twice and every security fix applied twice.

## Decision

The platform is **tenant-aware always and single-tenant by configuration**. On-prem is a
deployment with one `TENANT` row, not a separate code path. Every tenant-scoped table
carries `tenant_id` and has an RLS policy (ADR-002 defines the rule); global knowledge tables
— `RULE_PACK`, `RULE`, `VULNERABILITY_DEF`, `VENDOR_ADVISORY`, `ADVISORY_FIXED_PACKAGE` —
carry none. Child tables do **not** inherit scope through a foreign key — Postgres RLS does
not work that way. Every tenant-scoped table carries a **denormalised `tenant_id` and its own
RLS policy**, and every child table declares a **composite foreign key**
`(tenant_id, parent_id) REFERENCES parent(tenant_id, parent_id)`, so a child physically cannot
point at a parent in another tenant. That constraint is what makes the denormalisation safe
rather than merely fast.

The tables this applies to, none of which carry `tenant_id` in the v2 ERD as drawn:
`NETWORK_RANGE`, `SCAN_POINT`, `SCAN_POINT_CAPABILITY`, `POLICY_SCOPE_RULE`, `SCAN_TARGET`,
`SCAN_JOB`, `JOB_LEASE`, `SCAN_TASK`, `CREDENTIAL_GRANT`, `ASSET_IDENTITY_KEY`,
`ASSET_ADDRESS`, `SERVICE`, `SOFTWARE_COMPONENT`, `ASSET_RELATIONSHIP`, `EVIDENCE`,
`FINDING_EXPOSURE`, `FINDING_HISTORY`, `REMEDIATION`. `TENANT.deployment_mode`
records `saas` or `onprem` for the few genuinely mode-specific behaviours. There is no
compile flag, no build variant and no branch that removes tenancy.

## Alternatives considered

**A separate single-tenant build for on-prem.** Rejected: it is the two-products outcome
above. It also means the on-prem deployment — the one running in an environment we cannot
observe, at customers with the strictest security requirements — runs the code path with the
*least* test coverage.

**SaaS only, on-prem later.** Rejected on market grounds: air-gapped and on-prem customers
exist in this market and ask on the first call, and retrofitting offline operation, local
PKI and offline rule pack import into a SaaS-shaped system is far more expensive than
building for it from Phase 1.

**On-prem only, SaaS later.** Retrofitting tenancy into a single-tenant schema means touching
every table, every query and every access path, with a cross-tenant disclosure as the failure
mode of any row missed.

**Enforce child-table isolation with an RLS policy containing a subquery to the parent** —
`EXISTS (SELECT 1 FROM finding f WHERE f.finding_id = evidence.finding_id AND f.tenant_id = ...)`.
Correct, and it avoids denormalisation. Rejected on planning: the subquery is re-evaluated per
row and cannot be pushed into an index scan, so it degrades exactly on the largest tables
(`EVIDENCE`, `SCAN_TASK`) and on chains two or three levels deep from `TENANT`. A denormalised
column with a composite FK gives the same guarantee as a static constraint rather than a
per-query cost.

**Multi-tenant at the application layer, single-tenant database per customer in SaaS.**
Stronger isolation, considerably more operational surface, and it still needs `tenant_id`
plumbing for the shared knowledge data. RLS gives most of the benefit at a fraction of the
cost.

## Consequences

One codebase, one test suite, one security review. A SaaS feature works on-prem by
construction. The costs are carried everywhere: `tenant_id` on every tenant-scoped table and
tenant context in every query path, RLS session setup on every connection including background
workers, and a
small set of mode-conditional behaviours — chiefly PKI (ADR-018), self-update (ADR-022) and
offline signed knowledge import (ADR-019) — that must be genuinely conditional, not forked.
On-prem also carries obligations v1 did not budget: a diagnostics bundle command, structured
local logs with redaction, a published supported-version policy, and an offline update path,
all required from Phase 1.

## Review trigger

Revisit if a customer requirement forces true physical isolation — a regulated tenant that
cannot share a database instance — which would be an additional deployment topology rather
than a second codebase.
