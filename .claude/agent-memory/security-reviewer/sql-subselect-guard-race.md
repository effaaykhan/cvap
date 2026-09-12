---
name: sql-subselect-guard-race
description: An UPDATE whose guard comes from an uncorrelated subselect over the same table is not race-safe; the self-referential inline CASE is. Measured, both directions.
metadata:
  type: project
---

`UPDATE t SET c = CASE WHEN held THEN c ELSE $n END FROM (SELECT … FROM t WHERE pk=…) g`
evaluates `held` against the **statement snapshot**, not the locked row. Under READ
COMMITTED a writer that blocks on the row lock and then proceeds applies a stale guard
and clobbers the row it was written to protect.

The same predicate written **inline over the target row's own columns** (no `FROM`) is
race-free: Postgres re-evaluates the `SET` expressions against the updated tuple under
EvalPlanQual.

**Why:** measured on `Assets.SetAttribution`/`SetRelease` during the ADR-095 review
(2026-09-12) with two concurrent `db.Write` transactions and a channel holding the first
open. Subselect form: the inferred write overwrote the exact one, and because the two
setters re-snapshot separately it also produced an incoherent row — `distro_release` from
a band vote beside a `release_provenance` still claiming an exact host read, i.e. a
fabricated value labelled ground truth. Inline form under the identical interleaving: the
exact write survived, both columns coherent. **CVAP now ships the inline form** — do not
re-report it; re-report only if a subselect guard reappears.

**How to apply:** one Core sweeps serially, so this needs two correlating processes (a
second Core replica, or test/e2e's own Core against the same database — see the user's
[[host-core-shares-test-db]]). Rank Medium and always offer the inline rewrite: it is
strictly simpler and removes the subselect's coupling to `RowsAffected`/`ErrNotFound`.
Related: [[defect-store-guard-vs-return-value]].
