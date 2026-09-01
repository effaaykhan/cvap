# ADR-031: Enrolment tenant lookup is a one-value SECURITY DEFINER function

**Status:** Accepted
**Date:** 2026-09-01

## Context

ADR-002 makes every read tenant-scoped: `app.tenant_id` is set on the connection and RLS
filters against it. Enrolment cannot satisfy that. A scan point presents a client certificate
and nothing else (ADR-005), so Core must determine which tenant it belongs to *before* it can
set the tenant context — but `scan_points` is tenant-scoped, so reading it needs the context
being derived. Under `cvap_app` with `app.tenant_id` unset, the one-argument `current_setting`
raises, so the query does not merely return nothing: it fails. There is no arrangement of RLS
policies that resolves this, because the input to the policy is what is missing.

## Decision

One `SECURITY DEFINER` function, `tenant_for_scan_point(fingerprint text) RETURNS uuid`,
created in migration 0015, owned by the migration role, `EXECUTE` granted to `cvap_app` and
revoked from `PUBLIC`. It is the **only** deliberate exception to ADR-002 in the schema.

Because it is a hole through RLS, it is exactly one value wide. Each constraint is part of
the decision, not an implementation detail:

- **`RETURNS uuid`** — not a row, not `SETOF`. The caller gets a tenant id and nothing else.
- **`SET search_path = pg_catalog, public`** — a `SECURITY DEFINER` function without a pinned
  search path is exploitable by search-path manipulation, and this one runs as the definer.
- **`STABLE`, parameterised** — the fingerprint is a bind parameter, never interpolated.
- **Matches `cert_fingerprint` only, and only from an allowlist of enrollable statuses**
  (`pending`, `online`, `offline`). A `revoked` or `disabled` scan point does not resolve;
  a revoked certificate resolving to a tenant would defeat most of the point of revoking it.
- **Returns `NULL` on no match, and does not raise.** A distinguishable error is an oracle for
  whether a fingerprint is enrolled.
- **One indexed equality probe**, with a filter applied to the at-most-one row it can return.
  A hit does no more work than a miss, so enrolment is not leaked by timing either.
- **Not owned by `cvap_app`.** A `SECURITY DEFINER` function its caller can `CREATE OR REPLACE`
  is not a control — it is a way to run arbitrary SQL as the definer. Migration 0015 asserts
  the ownership rather than assuming it.
- **The definer must hold `BYPASSRLS` or `SUPERUSER`.** Every table carries
  `FORCE ROW LEVEL SECURITY`, which applies RLS to the owner too, so `SECURITY DEFINER` alone
  does not let this function read `scan_points`. On a cluster whose schema owner is a
  superuser this is true by accident; where it is not — a hardened on-prem deployment with a
  non-superuser owner, which ADR-002's "only migration roles bypass RLS" invites without
  guaranteeing — the function raises instead of returning NULL. That breaks enrolment *and*
  reopens the oracle this ADR closes, because a resolvable and an unresolvable fingerprint
  then fail differently for an environmental reason. Migration 0015 asserts it at migrate
  time. This is the constraint that fails silently in a deployment nobody tested, which is
  why it is written down rather than left to hold on its own.

In Go, the function is reached only by an unexported `DB.resolveTenant`, which runs outside
`Read`/`Write` and returns only a `TenantID`. It must never return a connection: the store's
whole design is that no code path obtains a connection without a tenant, and an enrolment path
handing back a live connection reopens exactly that. Callers resolve the tenant, then enter
`Write(ctx, tenant, …)` normally. The package's AST encapsulation test covers this.

The status allowlist defaults an unlisted value to "cannot enrol", which is the safe direction
but a silent one. `scan_point_status` therefore carries a `COMMENT ON TYPE` — and migration
0002 a matching note where the type is declared — requiring anyone adding a value to decide
here explicitly rather than inherit the default by accident.

## Alternatives considered

**A separate unscoped lookup table mapping fingerprint to tenant.** No RLS hole at all, which
is genuinely attractive. Rejected because the mapping is then duplicated and can drift from
`scan_points` — and the failure mode of drift is a scan point that authenticates to the wrong
tenant, which is worse than the narrow function this avoids. A trigger keeping them in sync is
more moving parts defending the same one value.

**A second database role with cross-tenant `SELECT` on `scan_points`.** The strongest
separation. Rejected on operational cost: a second connection pool and a second credential in
every deployment mode (ADR-017 includes air-gapped on-prem), to protect a lookup that is
already one column wide. It also needs an additional RLS policy permitting that role to read
across tenants, so the hole exists either way — just spread over more surface.

**Return the whole `scan_points` row, since enrolment needs the scan point anyway.** The
convenience argument, and the reason the width constraint is written down. Rejected: enrolment
can re-read the row through `Read(ctx, tenant, …)` once the tenant is known, at the cost of one
extra query. Returning the row would make this function a general cross-tenant read primitive
over the table that maps certificates to customers.

**Raise on no match, so enrolment failures are diagnosable.** Rejected: it makes the function
an enrolment oracle for anyone who can call it. Diagnosis belongs in Core's logs, where the
audit event already records the attempt.

**Defer the problem to the session that builds enrolment.** Rejected: the constraint shapes the
store's public API, and discovering it after `Read`/`Write` are fixed means either retrofitting
the API or bolting enrolment on beside it — which is how the "no connection without a tenant"
property gets lost.

## Consequences

Enrolment works without weakening RLS anywhere else, and the exception is one auditable object
with one output column rather than a policy everyone has to reason about. `security-reviewer`
has a single named thing to check.

The costs: this is now a permanent asterisk on ADR-002, and every future reader of the schema
who greps for `SECURITY DEFINER` must find the reasoning rather than a bare function. Enrolment
pays one extra query to re-read the scan point under tenant context. And the status allowlist
is a standing obligation on a type that will gain values — mitigated by the comments, but a
comment is not a constraint, and nothing mechanical will fail if someone ignores it.

## Review trigger

**Any request to return more than a tenant id from this function.** That is the change that
converts a lookup into a cross-tenant read primitive, and it should reopen this ADR rather than
be made in a migration. Also revisit if a second enrolment-time lookup appears needing the same
treatment — two exceptions is a pattern, and a pattern deserves a mechanism rather than a
second bespoke function.
