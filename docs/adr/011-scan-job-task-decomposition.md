# ADR-011: Scan / Job / Task three-level decomposition

**Status:** Accepted
**Date:** 2026-08-30

## Context

A scan of a /16 dispatched as a single unit of work has no partial progress, cannot spread
across scan points, and has catastrophic retry semantics: two hours in, one failure discards
everything. User intent, the unit of assignment and the unit of attribution are three
different things and cannot share one row.

## Decision

Work decomposes into three levels.

- **Scan** — user intent. "Assess corporate infrastructure." Holds policy, targets and
  aggregate status.
- **Job** — one unit assigned to one Scan Point, one engine, bounded to roughly minutes of
  work. The unit of leasing (ADR-012), retry and progress. Ranges are chunked into jobs at
  dispatch time.
- **Task** — individual target work inside a job. The unit of observation attribution.

Every observation is attributable to a task, every task to a job, every job to a scan.

## Alternatives considered

**One level: the scan is the dispatched unit.** The v1 reading. Rejected on retry cost and
progress reporting — a /16 as one job means no partial progress and a full restart on any
failure — and because it cannot spread one large range across several scan points in the
same zone.

**Two levels: scan and task, dispatching individual targets.** Removes the chunking problem
but creates a leasing problem: leasing, renewing and epoch-checking per individual host is
enormous protocol overhead for a /16, and progress becomes a count of millions of rows. The
job level exists precisely to be the coarse-grained leasing unit.

**Two levels: scan and job, with no task attribution.** Cheaper, and it is the tempting
shortcut once jobs exist. Rejected because observations then attribute only to a batch, so
"which target produced this" — needed for evidence, for exposure and for re-running a single
target during verification (§11 step 10) — is unanswerable.

## Consequences

Partial progress, cheap retry, and parallelism across scan points in a zone all become
natural. A job bounded to minutes keeps lease renewal intervals sane and bounds the work lost
to a lease failure. The costs are chunking logic at dispatch that must produce sensibly-sized
jobs across wildly different target types, three levels of status to aggregate correctly for
the UI, and more rows per scan.

## Review trigger

Revisit if job chunking cannot produce minutes-bounded jobs for some engine class — a
long-running crawler or a large repository SAST job are the likely candidates — in which case
the answer is engine-specific chunking, not a fourth level.
