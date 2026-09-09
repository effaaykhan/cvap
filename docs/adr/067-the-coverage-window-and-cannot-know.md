# ADR-067: The advisory coverage window is data, and a release past it is cannot-know

**Status:** Accepted
**Date:** 2026-09-09

Closes backlog **B29**, the last matching-integrity item before P3.4.

## Context

A release's advisory feed covers only until that release's support ends — EOL, or ESM end. A
host running a release **past that window** has real exposure the keyspace cannot know about:
the feed issued no advisories for the period after support ended, so backport-aware matching
(ADR-014) finds nothing and the host reads **clean**. That is a silent false negative — the
exact failure P3.1 was sequenced first to prevent, arriving from a different direction (P3.1
guarded against a wrong comparator saying clean; this is the feed itself running out).

It has not bitten on Metasploitable because hardy had ESM advisories through ~2012, so the
keyspace covers the host's exposure. It will bite on the first customer host past its window,
and it will look exactly like a clean result.

## Decision

Make coverage a **state the system reports**, never an absence it stays silent about.

### 1. The coverage window is DATA, ingested from the feed

`release_coverage` (migration 0036) records, per release, `release_date` / `support_expires` /
`esm_expires`, ingested from `ubuntu.com/security/releases.json` (`knowledge/usn_ingest.py
fetch-releases` / `import-releases`, the ADR-019 offline two-step). **esm_expires is the
coverage end** — the last date advisories flow, including ESM. A boundary in code drifts from
the feed it describes; this is the same argument as ADR-063's staleness threshold and ADR-024's
ceilings. Where the feed exposes real dates (focal ESM 2030, jammy 2032) they are used
directly; where it returns only a placeholder — for releases predating ESM tracking it returns
the release date for all three fields, e.g. hardy's degenerate 2008 — the row is marked
`coverage_source = 'feed-degenerate'` and the **empirical newest advisory** the keyspace holds
for the release is the honest display value. The out-of-coverage *decision* (`esm_expires <
now`) holds regardless: a degenerate 2008 date is still firmly in the past.

The decision uses esm_expires, **not** the newest-advisory date, deliberately: a currently
supported release in a quiet advisory period must not be judged out of coverage. Absence of
recent advisories is not absence of coverage; the support window is.

### 2. Matching returns a state — vulnerable / clean / cannot-know

`domain.ClassifyMatch(anyAdvisoryMatched, releaseInCoverage)` (pure) is the fourth application
in the project of **absence is not evidence**: no advisory for a package, no keyspace analogue
for a product (ADR-064), no labelled corpus instance for a rule (§5.5), and now **no advisory
coverage for a release**. A no-match on an out-of-coverage release is `cannot_know`, never
`clean`. A no-match with coverage *unknown* (no window recorded) is also `cannot_know` — an
unrecorded window cannot be presented as coverage.

A **positive** match stays `vulnerable` whatever the coverage: a found vulnerability is real;
coverage only bounds what might have been *missed*.

### 3. The three states are distinct and stay distinct

`matched-and-vulnerable`, `matched-and-clean`, and `cannot-know` are separate. The third
collapsing into the second is the entire defect. `domain.ClassifyMatch` and its test assert a
no-match produces a *different* state by coverage; the coverage state is computed server-side in
SQL from the window in the data (like feed freshness), never inferred in the UI.

### 4. Surfaced

The knowledge panel renders per-release coverage beside feed freshness (a stale feed and an
out-of-coverage release are two ways matching silently under-reports; an operator needs both).
The asset page carries a prominent caveat when a host's resolved release is out of coverage: a
finding list that shows nothing for it means *cannot-know, not safe*. A "clean" an operator
acts on that really means "unknown" is the harm B29 names, and it is now impossible to reach
without the state being on screen.

## Consequences

- Coverage is per-release, applied per-asset through the resolved release — a blanket
  completeness caveat on the host's matching, not a per-package flag.
- Advisory→finding production is not yet wired (that is P3.4+); `ClassifyMatch` is the classifier
  that consumer will call, and the state is demonstrated today through the coverage reads and the
  two surfaces (`TestReleasePastCoverageWindowIsCannotKnow`, `TestCoverageSurfaces`).
- `release_coverage` is the **seventh** knowledge table `cvap_knowledge_import` writes and the
  **sixteenth** table the v2 ERD does not draw. Recorded here and in the store `CLAUDE.md`
  global-knowledge list; folded into **B27** (redraw the ERD, supersede ADR-029), not a new
  per-table note.

## Acceptance

A host on hardy — ESM long ended, `esm_expires` degenerate/2008, out of coverage — reports
`cannot_know` for a no-advisory result, while the same no-match on jammy (ESM 2032, covered)
reports `clean`. Demonstrated, not asserted: `TestReleasePastCoverageWindowIsCannotKnow`
resolves the two against the real coverage data and shows the states differ.

## Review trigger

The degenerate-date case means the exact coverage-end is imprecise for pre-ESM-tracking
releases; the empirical newest-advisory date backstops the display, and the decision is robust.
Revisit if a feed other than USN (RHSA, DSA — B26) exposes coverage differently, or if a
supported release is ever wrongly judged out of coverage (it should not be, since the decision
keys on the support window, not advisory recency).
