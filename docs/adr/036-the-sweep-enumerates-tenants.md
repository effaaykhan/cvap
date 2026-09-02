# ADR-036: The sweep enumerates tenants, and that is the only unscoped read

**Status:** Accepted
**Date:** 2026-09-02

## Context

`Leases.ExpireLeases` carries the whole of ADR-012's at-most-once decision. A lease that ran
out means a scan point stopped renewing — it died, partitioned, or self-aborted — and the two
right answers diverge sharply:

- `reassign_safe` → back to `queued`. Passive discovery is safe to duplicate.
- not `reassign_safe` → `failed` with `termination_reason = 'lease_lost'`, and an operator
  escalation. Re-running active or intrusive work harms the customer's estate.

A security review of the Session 8 dispatch and ingest code found that function had **no
caller**. It was written, documented at length, and covered by tests that called it directly.
Nothing in Core would ever have run it. So a scan point that died mid-job left that job
`running` forever: never retried when retry was safe, never escalated when it was not. The
property existed only in the comment above the function.

The same review found `HeartbeatTimeout` in the same state: a constant, a comment saying
"Core times out at 90s", and no comparison against `last_heartbeat` anywhere. A scan point that
vanished stayed `online` in the operator's view indefinitely.

A caller has to be a periodic sweep, because the event it reacts to is the **absence** of one.
A dead scan point sends nothing, and the stream closing is not the signal either — a
partitioned scan point holds its lease and keeps scanning while its stream is long gone. Only
the clock knows.

That is where this collides with ADR-002. Every sweep query is tenant-scoped, so the sweep
needs the list of tenants; RLS on `tenants` means a `cvap_app` connection sees only the tenant
it is already scoped to. ADR-032 says the store exposes no unscoped path, and
`internal/store/CLAUDE.md` says so deliberately, with the note that whoever needs one should
make the case. This is that case.

## Decision

There is **one** unscoped enumeration in the system: `active_tenant_ids()`, created in
migration 0023, whose single caller is the dispatch sweeper.

**The SQL shape**, and the narrowness lives here rather than in a Go convention:

- `RETURNS SETOF uuid`. Not the row, not a record type. A sweep needs identifiers; returning
  the tenant record would make this a cross-tenant read primitive.
- **No parameters.** There is nothing to interpolate and nothing to probe with.
- `SECURITY DEFINER`, `STABLE`, `SET search_path = pg_catalog, public`. Read-only: it cannot
  be the write half of anything.
- `WHERE status = 'active'` only. A suspended tenant's jobs are not swept, which is the
  conservative direction — a lease left `granted` expires nothing, it does not re-dispatch.
- `REVOKE ALL FROM PUBLIC`, `GRANT EXECUTE TO cvap_app`, owned by the migration role. The
  migration asserts the owner is not `cvap_app` and does hold `BYPASSRLS` or `SUPERUSER`,
  because every table is `FORCE ROW LEVEL SECURITY` — an owner without it would make the
  function return nothing, and a sweep that finds no tenants looks exactly like a sweep with
  nothing to do.

**The Go shape.** `DB.ActiveTenantIDs(ctx) ([]TenantID, error)` and nothing wider. Core-side
only: nothing reachable from a wire handler may call it, because a scan point's request
already resolves to exactly one tenant through the ADR-033 class, and a handler needing the
whole list would be a handler acting outside the tenant that authenticated it.

**This is not an ADR-033 member.** That class is *resolution* — one credential in, one tenant
out — and every member returns `(TenantID, error)`. This is *enumeration*, a different shape
with a different justification, and folding it into ADR-033 would loosen that class's one
testable property. `encapsulation_test.go` keeps them separate:
`TestSweepEnumeratorStaysNarrow` pins the parameter count and the element type,
`TestNothingElseTouchesTheRawPool` fails the build for any third function reaching the pool.
Both were sabotage-tested by widening the return type and by adding a filter argument.

**The escalation commits with the expiry.** The sweeper writes the `job.lease_lost` audit
event in the same transaction as `ExpireLeases`. An escalation recorded afterwards is one a
crash can drop, leaving a job marked `failed` and no record that anybody was meant to look
at it.

## Consequences

Anything holding `cvap_app` can enumerate tenant ids. That is a real widening and is stated
rather than glossed: it leaks the number of tenants and their identifiers to a compromised
Core process. It buys the enforcement of ADR-012, and every alternative shape is worse — a
`SECURITY DEFINER` function that performed the sweep itself would be a **write** bypassing RLS
across every tenant, which is a far larger hole than a list of uuids.

The sweep interval must stay below the lease TTL. A sweep slower than the TTL leaves an
expired lease `granted` for up to one interval, which delays a requeue and, worse, delays the
operator escalation on a job that must not retry.

`Sweeper.Run` never returns an error. A transient database failure must not stop the loop: a
supervisor that restarted the process on one would turn a blip into an outage of the thing
that enforces ADR-012.

## Review trigger

Any request to widen `active_tenant_ids()` — a second column, a parameter, a `SETOF record` —
and any second unscoped enumeration. Two would be a pattern, and this ADR chose one function
precisely so there is nowhere for a second to hide. Also revisit if the sweeper ever needs to
run in more than one Core process at once: `ExpireLeases` uses `FOR UPDATE SKIP LOCKED` so
concurrent sweepers are safe, but the audit event volume is not deduplicated.
