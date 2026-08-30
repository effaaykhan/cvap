# ADR-016: Observations partitioned monthly, 90-day default retention

**Status:** Accepted
**Date:** 2026-08-30

## Context

Observation-first (ADR-006) means every scan writes a row per thing seen, from every vantage
point, on every run. `OBSERVATION` is the growth vector of the entire system: a weekly scan of
a large estate writes it continuously, at a rate that dwarfs findings and the evidence attached
to them. Unbounded growth there degrades every query in the database, and retention has to be
decided in the migration that creates the table rather than after it fills.

## Decision

Partition `OBSERVATION` **by month**. Raw observations retain **90 days by default**; derived
findings retain indefinitely. Pruning observations is dropping a partition, not a bulk delete.
`FINDING_HISTORY` is a state-change log — one row per transition, never a row per finding per
scan — so a weekly scan of 10,000 findings does not write 10,000 rows a week. Partitioning is
declared in the migration that creates the table (ADR-002's same-migration rule applies to
partitioning as well as RLS).

The governing rule, which covers every case rather than enumerating exceptions:

> **Observations are ephemeral. Anything that must outlive them is copied at the moment it
> becomes load-bearing.**

Three instances follow from it, and it forecloses a fourth:

- **Merge evidence** is copied into `ASSET_IDENTITY_KEY` at merge time (ADR-007).
- **Finding evidence** is copied into `EVIDENCE` at finding creation.
- **Verdict payloads** (ADR-006) are copied into `EVIDENCE` when the verdict produces a
  finding. Verdict observations therefore need no exemption — they drop on the normal 90-day
  clock, because what mattered has already been copied.

Consequently **`EVIDENCE.observation_id` is a nullable soft reference for provenance, not a
hard foreign key.** It goes null when the observation's partition drops. A hard FK here is the
dangling-reference bug: it would either block the partition drop or fail it.

**`EVIDENCE` is not partitioned.** Partitioning earns its keep when you bulk-drop by time, and
evidence is not dropped by time — it follows its finding (ADR-015). Volume does not justify it
either: ADR-015 puts large artefacts in the object store, so rows are small, and evidence
exists per finding rather than per probe — low hundreds of thousands of rows against millions
of observations at MVP scale. This supersedes architecture-v2 §9.1 and `execution-plan.md`
§4.3, both of which say `EVIDENCE` is partitioned from day one.

## Alternatives considered

**No partitioning; delete old rows on a schedule.** Rejected: bulk deletes on the largest
table in the system produce sustained vacuum load and index bloat exactly when the system is
busiest. Dropping a partition is metadata-only.

**Partition by tenant instead of by time.** Rejected: it addresses isolation, which RLS
already handles (ADR-002), while leaving the actual growth problem — time — unsolved, and it
creates an unbounded partition count that grows with sales.

**Weekly or daily partitions.** Finer pruning granularity, at the cost of a partition count
that makes planning slower and maintenance noisier. Monthly matches the 90-day retention with
three or four live partitions, which is the right trade.

**Partition `EVIDENCE` too, as architecture-v2 §9.1 originally specified.** Rejected, and the
reason it was specified is worth naming: retrofitting partitioning onto a populated table is
painful, so the instinct is to partition anything that might grow. But evidence has no time-
based drop, so there is no partition key that matches how it is actually pruned — partitioning
by capture time would buy a mechanism we never use while fixing the wrong key permanently.
Deciding not to partition now is cheaper than deferring the key choice past the creating
migration.

**Retain observations indefinitely.** Attractive because re-runnable correlation (ADR-006) is
more valuable over a longer window. Rejected on cost: observations are the growth vector, and
the analytical value of a nine-month-old observation is low once findings are derived.

**Put `EVIDENCE` on the same 90-day clock as observations, for one uniform mechanism.** By far
the simplest, and the reason this needs stating explicitly. Rejected: findings retain
indefinitely, so a finding would outlive the evidence proving it — and ADR-015 rejects
discarding the full artefact precisely because it is what makes a disputed finding defensible.
A finding nobody can substantiate is worse than one that costs storage.

## Consequences

Observation pruning becomes cheap and predictable, and the largest table stays queryable.
Every open finding can always be substantiated by its evidence, and merges stay reversible for
the life of the asset, because in each case the load-bearing data was copied rather than
referenced. One rule replaces a growing list of special cases, and the next thing that must
outlive an observation is covered by it without another ADR.

The costs: 90 days bounds how far back correlation can be re-run after a bug fix, which is a
real limit on ADR-006's promise and must be communicated honestly; queries spanning partitions
need sensible time predicates; partition creation must be automated, because a missing future
partition is an ingest outage; copy-at-derivation duplicates data, so redaction must be applied
to the copy as well as the source; provenance degrades rather than persists, since
`EVIDENCE.observation_id` goes null once the source partition drops and the UI must present
that honestly; and `EVIDENCE` growth is bounded by finding lifetime rather than by a retention
window, with no partition to drop if that estimate proves wrong.

## Review trigger

Revisit the retention default if design partners repeatedly need to re-run correlation over a
window longer than 90 days, and revisit partition granularity if monthly partitions grow large
enough to make index maintenance within a single partition painful. **Revisit `EVIDENCE`
partitioning at Phase 4**, with measured row counts from credentialed assessment rather than an
estimate — that is the first phase that generates evidence at volume.
