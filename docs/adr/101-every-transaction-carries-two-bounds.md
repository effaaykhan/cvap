# ADR-101: Every transaction carries two bounds, because statement_timeout is not one

**Status:** Accepted
**Date:** 2026-09-21
**Follows:** ADR-058 (the load gate's coarse ceiling — where the numbers come from), ADR-098 (the
finding list is as slow as the plan the driver reaches; the generic plan pgx reaches after five
executions), ADR-100 (the identity queue's measured pages), ADR-002/041 (the pool: `SET LOCAL`
inside a transaction, always, because the database is what cannot forget).
**Closes:** B50's first half — the bound. The plan robustness work (B48, the `($n IS NULL OR col =
$n)` idiom at eight remaining sites) is deliberately NOT in this ADR.

## The problem, stated exactly

No operator read carried a bound of any kind. A fresh tenant's finding list reached a plan nobody
had measured and ran for **91 minutes**, holding a pooled connection for all of it, and nothing in
Core, in the store or in the database stopped it.

That is not a performance defect. A slow page and an unbounded page are different kinds of thing:
the first is a number you can put in an SLO, the second is a resource an unauthenticated-adjacent
request can hold until the pool is empty. B48 makes the particular query fast. This ADR makes
**every** transaction finite, including the next one to regress, which nobody has found yet.

## What was measured

Three measurements, run against a migrated `cvap_test` on PostgreSQL 16 before anything was
designed. The third is the one that changed the design.

| measurement | result |
|---|---|
| one statement over budget: `statement_timeout = 500ms`, `pg_sleep(5)` | cancelled, **SQLSTATE 57014**, "canceling statement due to statement timeout" |
| an `INSERT` committed earlier in that same transaction | **0 rows survive** — the timeout rolled it back |
| **three `pg_sleep(0.8)` statements in one transaction under `statement_timeout = 1s`** | **all three completed, 2.4 s total, none cancelled** |

The third result is the whole reason this ADR is not one line long. `statement_timeout` is reset for
**every statement**. It bounds a statement; it does not bound a request. A callback issuing N
statements may run for N × budget and never trip it — a bound stated over the request and enforced
over the batch, which is the shape [guard-scoped-to-the-batch] records and which holds in every
hand-written fixture because hand-written fixtures issue one statement.

So "a per-request `statement_timeout` via `SET LOCAL`" — the shape B50 was filed with — would have
produced a control that reads correctly, tests green, and does not bound the thing it names.

## Decision

`inTx` applies the budget **twice**, and neither application is redundant.

1. **A context deadline**, which bounds the WHOLE transaction. This is the bound that actually
   holds. pgx cancels the in-flight query when it expires.
2. **`SET LOCAL statement_timeout`**, which bounds EACH statement and is enforced by the database
   rather than by us. This is the one that survives a caller who detaches the context, and it is
   what turns a runaway single statement into a fast, attributable 57014 rather than a client-side
   cancel that leaves the server still working.

The GUC is set with `set_config('statement_timeout', $1, true)` and **verified on the same round
trip**, exactly as `app.tenant_id` is and for exactly the same reason: a GUC that silently failed to
take leaves the transaction unbounded while believing it is bounded, which is worse than being
unbounded honestly. The verification compares by casting both sides to `interval`, because
`set_config` returns the NORMALISED value (`30s` for `30000`) and a string compare against what was
sent fails on a setting that took perfectly.

A zero or negative budget is **rejected**, not treated as unbounded. Unbounded is the state this
ADR ends; it must not be reachable by passing zero.

### The numbers

| budget | value | who gets it |
|---|---|---|
| `OperatorBudget` | **30 s** | `DB.Read` and `DB.Write` — the defaults, so a caller who never heard of a budget still has one |
| `BulkBudget` | **120 s** | exports, sweeps, the correlator, ingest |

Thirty seconds is roughly thirty times the slowest page anyone has measured: ADR-058 sets the
coarse ceiling at 1000 ms for the finding list and 600 ms for the asset list, ADR-098 measured that
list at 37 ms custom / 95 ms generic after the LEFT JOIN, and ADR-100 measured a full identity-queue
page at ~540 ms before paging and well under that after. The budget is not a target and is not an
SLO — it is the distance between a slow page and an unbounded one. Nothing measured comes near it;
anything that reaches it is a plan nobody measured.

Per-package budgets, each stated where it is spent:

- `correlateBudget = BulkBudget`. A sweep reads every unresolved observation for a tenant by design.
- `dispatchBudget = OperatorBudget`. A handover, an ack and a lease renewal are single-row
  statements; none has any business taking thirty seconds, and these are the transactions that
  decide what goes on a wire.
- `ingestBudget = BulkBudget`. A submission arrives in chunks of thousands of rows via `SendBatch`.

## What a timeout does to a WRITE

A read that aborts returns an error and nothing is lost. **A write that aborts rolls back, and takes
everything in the transaction with it** — including a record of why it refused.

This project has three recorded instances of a rollback swallowing the record of its own refusal
(`internal/store/CLAUDE.md`: the login lockout counter, the OIDC browser binding, ingest's ledger
conflict). The prescribed fix is for a refusing closure to return `nil` and carry the refusal out in
a captured variable, so the record commits.

**The budget introduces a fourth way to lose that record, and the prescribed shape does not fix
it.** If the transaction times out, the audit event rolls back whether or not the closure returned
nil. Measured, not reasoned about: the `INSERT` in the second row of the table above.

The paths where this can discard a refusal audit event:

1. **`handlers_auth.go` login** — `RecordFailure` plus the `auth.login_failed` audit event. A
   timeout here means the attempt happened, the failed-attempt counter did not advance, and nothing
   durable records it.
2. **`handlers_auth.go` changePassword** — the same `RecordFailure`.
3. **`oidc.go` browser binding** — the single-use state is consumed with `DELETE ... RETURNING`; a
   timeout un-deletes it, leaving the state redeemable. This one is a rollback that *restores* an
   attacker-useful condition rather than losing a record, which is why it is listed separately.
4. **`internal/dispatch/ingest.go`** — already structured around an unavoidable abort
   (`errConflictResume` re-asks in a fresh transaction), so it is the one path that already has the
   right shape for this.
5. **The identity queue's `identity.refused`** (ADR-100) — already written in its own transaction,
   which is the pattern the others would need.

**What is done about it here:** every caller checks the transaction error BEFORE the refusal
variable, so a refusal that was not recorded is never reported as though it was. That ordering was
already correct in all three instances and is now load-bearing rather than incidental, and it is
stated in `ErrStatementTimeout`'s doc comment. The login handler's flat 500 gains an explicit
timeout branch (see below).

**What is NOT done about it:** moving these refusal records into their own transactions, the way
ADR-100's `identity.refused` already is. That is the durable fix and it is a separate change — it
changes when a record becomes visible relative to the decision, which deserves its own argument.
Filed rather than smuggled in here.

## The response

`ErrStatementTimeout` maps to **504 Gateway Timeout**, code `timeout`, with the request id — the
only handle joining the response to the log line, which `writeError` emits at Error level because
the status is ≥ 500. The message does not invite a retry: a retry runs the same plan and spends the
budget again. A timeout is a signal to profile.

`timeout` is a separate code from `internal` because they ask the operator for different things — a
bug report versus a query to profile — and an alert that cannot tell them apart pages the wrong
person, which is the argument ADR-002 makes for splitting `ErrTenantIsolation` from
`ErrNotPermitted` on one SQLSTATE.

Two discriminations are needed to get there, both on messages, both following the existing 42501
precedent:

- **SQLSTATE 57014 is both** "canceling statement due to statement timeout" (our bound: 504) **and**
  "canceling statement due to user request" (a client cancel: not a 504, nobody is waiting).
- **`context.DeadlineExceeded` is the bound**; `context.Canceled` is the caller leaving.

Because neither spelling is guaranteed — a deadline can arrive as either — `inTx` also reads its own
deadline after the callback returns and wraps the error itself. The bound is attributed from our
side rather than guessed from message text.

**The login path is a deliberate exception that needed widening.** `handlers_auth.go` login does not
call `storeError`, because `storeError` maps `ErrNotFound` to 404 and on a login endpoint that is a
user-existence oracle; every fault there is one flat 500. A timeout is the one fault that carries no
signal about the user — it is a property of how long a statement took — so it is checked explicitly
and answered 504, leaving the anti-oracle default intact for everything else.

## Health

`GET /v1/health` gains `timed_out_requests`, `last_timeout_at`, `operator_budget_seconds` and
`bulk_budget_seconds`, so the surface states the bound it is measuring against instead of leaving it
in the source.

The count is **per tenant**, and that is the reason it is a keyed meter rather than a counter: a
process-wide number would tell tenant A that tenant B is running something slow. Every other number
on `HealthResponse` is tenant-scoped by an RLS-protected query; this one is held in memory and has
to earn the same property in Go.

What it does not claim, stated in the field's own doc string rather than only here: it is **in
memory and per-process**. Zero means "none since this Core started", not "none ever", and two Cores
against one database each report their own. A durable per-tenant timeout ledger is a table, a
migration and a retention policy — knowingly unfinished, and deliberately not smuggled into the
change that establishes the bound.

## What this ADR does not do

- It does not make anything faster. B48 is the plan work: eight statements still use the
  `($n IS NULL OR col = $n)` idiom that ADR-098 measured estimating one row under the generic plan.
  The bound is what makes a regression there survivable; it is not the fix.
- It does not bound the pre-tenant resolution path (`resolvePreTenant`, ADR-041), which queries the
  raw pool outside `inTx`. Three single-row `SECURITY DEFINER` lookups, one of which runs on every
  operator request. Named here so it is a decision rather than an omission.
- It does not retry anything. A budget is not a circuit breaker.

## Consequences

A runaway statement now costs 30 seconds and a 504 instead of 91 minutes and a held connection.
A sweep that cannot finish makes no progress and says so, rather than making partial progress:
`resolveHost` is one atomic decision by construction, so a timeout rolls the whole decision back and
the next sweep does it again.

The dispatch bound does not weaken lease fencing, and the direction is what makes that true. Every
fenced write carries its epoch in the `WHERE` clause, so the database decides. A transaction that
times out **commits nothing**, which is indistinguishable from a lease check that refused, and
non-negotiable #7 — a non-`reassign_safe` job fails on lease loss and does not retry — is the path a
timeout already takes. The unsafe direction would be a timeout that let a write land *without* its
epoch check, and a rollback cannot produce one.

The cost is a new failure mode on every write path: a refusal can now be decided and not recorded.
That is real, it is measured, and the mitigation here is ordering plus a test that pins it, not a
claim that it cannot happen.
