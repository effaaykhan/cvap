---
name: adr101-bound-findings
description: S44/ADR-101 (per-transaction budget) — commit-in-doubt is real (a timed-out tx CAN commit), the ADR-051 in-flight scope re-check fails open at exactly 30 s, kill latency and ActiveTenantIDs are unbounded. Measured 2026-09-21.
metadata:
  type: project
---

ADR-101 put a context deadline + `SET LOCAL statement_timeout` on every `inTx`
(`OperatorBudget` 30 s for Read/Write and dispatch, `BulkBudget` 120 s for
correlate/ingest/export). Audited commit 64cb120 by measurement. Check these
first in any later audit of a timeout/budget change.

**Why:** the ADR asserts "a transaction that times out COMMITS NOTHING, which is
indistinguishable from a lease check that refused" and that the unsafe direction
"a rollback cannot produce". Both halves of that are wrong in a measurable way.

**How to apply:**

1. **Commit-in-doubt.** If the deadline lands on the COMMIT round trip, the tx
   COMMITS and `WriteWithin` still returns `ErrStatementTimeout`. Reproduced
   51/240 with a Go-side sleep sweeping the deadline across the commit; the
   commit window measured ~6.8 ms wide on the dev DB. Safe sub-case: if the
   deadline expires *before* `tx.Commit` is called, pgx returns "context already
   done" and sends no COMMIT.
   - Consequence measured end to end in `PlanScan`: plan commits, error returns,
     `PlanPending` marks the scan `failed` (`scan.planning_failed`),
     `Scans.Cancel` then refuses (`ErrScanNotCancellable`), and `Jobs.Claim`
     excludes only `cancelled`/`killed` — so the queued jobs dispatch and put
     targets on a wire under a scan the operator sees as failed and cannot stop.
     `Jobs.CancellableFor` also matches only `cancelled`/`killed`.
   - Consequence measured in `offerWork`: `credential_grants` row +
     `credential.granted` audit with `delivered_to_fingerprint` commit while
     nothing reaches the wire (4/9 deltas). Reproduce deterministically with a
     `credsource.Resolver` that reads `ctx.Deadline()` and sleeps until
     `deadline - delta`, sweeping delta 21–29 ms.
2. **The in-flight scope re-check fails OPEN on the new error.**
   `scopeNarrowedForJob` / `windowClosedForJob` return `false` on any read error.
   With `policy_scope_rules` unreadable the renewal is GRANTED after 30.008 s for
   a job whose only target the live policy excludes; the same renewal is refused
   in 6.5 ms on a healthy DB. The fail-open was written for "a database blip";
   a bound makes it deterministic and simultaneous for every in-flight job.
3. **Budgets compose above the transaction.** One lease renewal issues three
   bounded transactions: measured 60.037 s to answer with `scan_policies` locked,
   which is ≥ `store.LeaseTTL` (60 s) — the lease expired while Core answered.
4. **ADR-024's 10 s kill bound.** `killCoversScanPoint` EXISTS-joins `scan_jobs`,
   so a stall there blocks even a tenant-scoped kill read; the pump is serial
   (kills → cancels → offerWork, 30 s each). Control 1.94 s; under a `scan_jobs`
   stall the kill was still undelivered at 240 s.
5. **`db.ActiveTenantIDs` is unbounded** (raw `db.pool.Query`, no deadline, no
   GUC) and is the first statement of BOTH the dispatch sweeper (ADR-012 lease
   expiry + planning) and the correlator. Measured blocked >75 s. ADR-101 names
   only `resolvePreTenant` as the exception, and ADR-102's follow-up bounded that
   one and again missed this.

Forcing function used throughout: an `ACCESS EXCLUSIVE` lock from a superuser
connection (`postgres://cvap:cvap_dev_only_password@…/cvap_test`) on the table
the path reads — it makes a statement reach the budget deterministically.
Cut-off probes (a parent ctx deadline swept across a measured baseline duration)
reproduce the same code path as the real 30 s budget because
`context.WithTimeout` keeps the earlier deadline.

Clean under the same method: the correlator (40 cut-offs, no partial state),
the sweeper's at-most-once accounting (30 cut-offs, failures always equal
escalation audits), and the START-side scope check (withholds work, never
dispatches a stale or empty allowlist). See [[dispatch_scope_and_kill_gaps]].
