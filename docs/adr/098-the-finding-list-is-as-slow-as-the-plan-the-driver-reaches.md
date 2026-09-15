# ADR-098: The finding list is as slow as the plan the driver reaches — the shape is decided by measuring both plans, and the load gate budgets each measurement

**Status:** Accepted
**Date:** 2026-09-15
**Follows:** ADR-058 (the coarse ceiling in CI, and its verdict that the paginated list does not
overshoot), ADR-069 (the computed priority order), ADR-074 (the categorical exposure term), and
the S37 regression fix (`c062a64`, "derive the zone set once, not per finding").
**Closes:** B47 — both halves: the query, and the gate whose single budget let the first slow path
silence the three measurements after it.

## What was measured

The load gate ran in CI for the first time since the db-gates chain went green and failed its own
coarse ceiling: finding list p95 @50k, exposure 1.0 = **1298 ms** against 1000 ms; the exposure-2.4
variant then ran the job into its 15-minute timeout, and exposure-by-zone and ingest throughput
reported nothing. B47 named the suspect the test's own comment names — the per-row
`count(DISTINCT zone_id)` — and asked for `EXPLAIN ANALYZE` on the shape rather than the endpoint.

The shape was profiled on the dev database (PostgreSQL 16.15, `jit = on`, the defaults for the
three JIT cost thresholds) against two tenants a previous run had left seeded at 50k findings, one
at exposure 1.0 and one at 2.4. Two mechanisms, one shape, and neither is the named suspect.

**The named suspect does not run per row.** In every plan mode the `count(DISTINCT)` subplan
executes **50 times** (`loops=50`): the planner defers an expensive target-list expression past
the Sort and the LIMIT (`make_sort_input_target`). ADR-058's verdict — fifty subqueries whether
there are five thousand findings or five hundred thousand — is still true at execution. It is
the *estimate* that is wrong: the planner charges the subplan for all 50 000 rows, and the
priority score's correlated `EXISTS` twice over (once as the sort key, once as an output
column), for a total plan cost of **2 120 373** against a real cost of about 24 000.

**Mechanism 1 — the custom plan pays for JIT.** With literal parameters (what `EXPLAIN` shows, and
what pgx sends for a statement's first five executions) the inflated estimate crosses
`jit_optimize_above_cost` and `jit_inline_above_cost` (500 000), so every execution compiles
83 LLVM functions: **~600 ms of a 665 ms warm execution** is `Optimization` + `Emission`.
`SET jit = off` on the same query, same tenant: **70 ms**, identical at both exposure depths.

**Mechanism 2 — the generic plan nests every join.** pgx caches prepared statements; after five
executions Postgres compares the generic plan's estimate (526 — it estimates *one row*) against
the custom plan's (857 977) and switches to generic for the rest of the run, which is the plan the
load test's 320 requests and every production page actually execute. No JIT there; instead the
one-row estimate makes the planner choose nested loops throughout — a seq scan of `rules` per
finding, `vulnerability_defs` per finding, and the exposure `EXISTS` as a **per-row nested loop
into `scan_zones`** — 50 000 iterations each: **628 ms** (1.0) and **766 ms** (2.4). The one-row
estimate comes from the optional-filter idiom: `($n IS NULL OR col = $n)` is estimated at ~0.5 %
selectivity per clause when `$n` is an unknown parameter, and four of them compound to nothing.

The S37 fix (`c062a64`) stated that the tenant-keyed zone subquery "evaluates once as an
InitPlan" and the per-finding `EXISTS` becomes an index lookup. **Neither plan mode produces an
InitPlan**: the custom plan hashes the whole `finding_exposure ⋈ scan_zones` subquery once
(and charges its estimated size per row, which is mechanism 1), and the generic plan runs it as
the nested loop above (mechanism 2). The commit's measured improvement was real — the hashed
subplan replaced a worse join — but the mechanism it named was not the one at work. That is the
same shape as B46's gRPC claim, in-house: a comment asserting how a third party (here the
planner) behaves, unmeasured, that later reads as a guarantee.

Why the S37 numbers (110 ms locally) and the S21 numbers (4 ms, ADR-058) were true when
measured: S21's list was ordered by an indexed timestamp, so it read a page; ADR-069 made the
order a computed score, so every finding is scored before the page is known — the query became
a scan-and-sort of the tenant and every correlated expression in the score is now evaluated at
tenant scale. S37 measured before the generic plan was reached, or on a runner where LLVM was
cheaper; the CI run that opened B47 was the first to run 320 requests with the db-gates chain
green.

### The three shapes, measured

| shape                                                               | custom plan | generic plan |
|---------------------------------------------------------------------|-------------|--------------|
| as shipped (correlated EXISTS, per-row count, `IS NULL OR` filters)  | 665 ms (JIT 597) | 628 / 766 ms |
| exposure set as a LEFT JOIN, count after the LIMIT, idiom kept       | 37 ms       | 473–586 ms   |
| the same, filters composed into the SQL only when set                | **37 ms**   | **91–100 ms**|

Warm, on the dev box, both exposure distributions within noise of each other. The status-filter +
cursor variant under the generic plan: 115 ms. The precise SLO is 500 ms.

## Decision

**The finding list's shape is chosen so that both plans the driver can reach are fast, and the
choice is recorded as a measurement, not a comment.** Three changes to `Findings.List`, none to
its semantics or its column order:

1. **The external/dmz exposure term is a `LEFT JOIN` against the set of externally exposed
   finding ids** — one `DISTINCT` scan of `finding_exposure` joined to `scan_zones`, keyed on the
   tenant parameter — and the term is `ext.finding_id IS NOT NULL`. No correlated subplan in the
   score, so nothing in the sort key is charged or executed per finding beyond a hash probe. The
   estimate drops below every JIT threshold (24 000 vs 500 000), and the generic plan has nothing
   to nest.
2. **The exposure count is computed in the outer query, after the LIMIT.** It is fifty index
   lookups by construction, not because the planner chose to defer it; the estimate now says
   what the execution does.
3. **Optional filters and the cursor are composed into the SQL only when present**, each with its
   own positional parameter. The planner sees the predicates that are there; the no-filter page —
   the common one — is estimated at the tenant's row count under both plan modes.

**What is deliberately not changed.** `jit` stays on: the defect was an estimate thirty times
reality, and the thresholds behaved correctly given it; turning JIT off for the application role
would have hidden the estimate's error rather than fixing it, and left the generic-plan mechanism
untouched. No SLO moves: the measurement says the published 500 ms is met with margin under both
plans. No materialised exposure count: the count already costs fifty index lookups per page, and a
maintained column would add a writer to a fact `finding_exposure` already holds (§5.2). The
`count(DISTINCT zone_id)` stays a DISTINCT-per-finding count (ADR-010).

**The gate budgets each measurement.** `sampleP95` runs each measurement inside its own budget —
every request at that measurement's coarse ceiling (320 × 1000 ms for the finding list) — and a
measurement that overruns stops, **fails its own gate**, and prints the p95 of the sample it did
complete. A measurement that cannot finish 320 requests at the coarse ceiling has failed the
ceiling on average, so stopping early loses nothing the gate would have said, and the
measurements behind it run. Each is its own subtest, so `-run` can target one and the log
names each. The two exposure-by-zone trend measurements borrow the finding list's ceiling as a
budget and print a truncation rather than fail, because ADR-058 publishes no SLO for them. The
Makefile's `-timeout` is now the *sum* of the budgets (40 m worst case, a few minutes healthy),
not a budget of its own. `TestMeasurementBudgetTruncatesAndSaysSo` proves the truncation path
DB-free, next to ADR-058's independent-halves test.

**What the gates say once they can run** is recorded below rather than in the backlog, because
"never reported" is the state B47 asked to end.

## What this changes for the other list queries

The `($n IS NULL OR col = $n)` idiom is in eight other statements (`assets.go` list and export,
`scans.go`, `identity_queue.go`, `findings.go` export). The asset list measured 89 ms in the same
CI run and is not touched here; its order is an indexed timestamp, so a nested generic plan reads
a page, not the tenant. The idiom is a hazard wherever a computed order or an unpaginated read
meets it — filed as B48 with the plan shape to look for, not fixed here, because none of those
surfaces has a measurement saying it is slow and this ADR does not fix by pattern.

## Consequences

- The finding list answers in ~40 ms (custom) / ~95 ms (generic) at capacity on the dev box, both
  exposure distributions, with the plan estimate within 2× of reality; a future regression in
  either plan mode is a load-gate failure with a number, not a timeout.
- `EXPLAIN` with literal parameters shows the custom plan only. A query pgx executes more than
  five times runs under whichever plan Postgres picks; profiling the shape means `PREPARE` and
  both `plan_cache_mode` settings, and that is what "EXPLAIN ANALYZE on the shape" means from
  here on (§5.17).
- A gate with one budget over several measurements reports the first failure and hides the rest;
  from here each measurement carries its own (§5.18).
