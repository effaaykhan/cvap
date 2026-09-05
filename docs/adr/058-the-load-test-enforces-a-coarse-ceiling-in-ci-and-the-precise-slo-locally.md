# ADR-058: The load test enforces a coarse ceiling in CI and the precise SLO locally

**Status:** Accepted
**Date:** 2026-09-05

## Context

Session 21 built a 10k-asset load test against the published SLOs (execution-plan §5): asset
list p95 ≤ 300ms, finding list p95 ≤ 500ms, observation ingest ≥ 5000/sec. It measures through
the real handler chain (RLS, the keyset query, JSON serialization) with an in-process server,
so the number it produces is the one the SLO names.

Two questions had to be answered before it could gate anything.

**Does a p95 SLO belong in CI at all?** A p95 latency assertion at the exact published threshold
is the archetype of a flaky gate on shared infrastructure: a GitHub runner under a noisy
neighbour will cross 500ms on a query that takes 40ms on a quiet machine, and a gate that fails
on the weather is a gate people learn to re-run until green and then to mute. A muted gate
enforces nothing, which is worse than no gate, because it still reads as coverage.

**Was the exposure overshoot session 21 predicted real?** ADR-010 stores one exposure row per
zone per finding, so a finding seen from several vantage points has several rows; the finding
list's per-row `count(DISTINCT zone_id)` was expected to overshoot the 500ms SLO at the ~2.4
rows-per-finding distribution a multi-vantage deployment produces (a distribution the pipeline
has never actually generated, but the aggregation must survive it). The verdict was deferred to
here with an instruction: say whether it is an index gap or an inherent cost, and revise the SLO
or the code accordingly — do not adjust the SLO to fit the measurement.

## Decision

**The load test enforces two bounds, and CI enforces only the coarser one.**

- A **coarse ceiling** at 2× each latency SLO (and SLO/2 for the throughput floor) runs always,
  including in `make ci` and GitHub CI. It is an order-of-magnitude bound: a regression that
  matters — a dropped index, a lost partition prune, an N+1 introduced by a new join — is
  order-of-magnitude, and 2× catches every one of those while sitting far enough above runner
  noise that it does not fire on the weather.
- The **precise SLO** (the published §5 number) runs only when `CVAP_RUN_LOADTEST=1` is set:
  a developer's quiet machine and the nightly job. It is a real gate, run where the machine is
  quiet enough for it to mean something.

2× is correct rather than a concession. The gate's job is to catch a real performance
regression, and a real one is not 1.2×; a gate at 1.2× catches nothing a human would call a
regression and fires constantly on noise. The coarse ceiling is the gate that runs on every
push; the precise SLO is the one that runs where it can be trusted.

The split is one function, checked both ways: `checkLatency` / `checkThroughput` are pure, and
`gate_test.go` sabotages each half independently (lift the coarse ceiling out of reach → only a
coarse-breach case fails; disable the precise comparison → only a precise-breach case fails).
Neither mutation is caught by the other's case, which is what makes "two independent halves" a
fact rather than a claim.

**Every measured number is printed on every run**, coarse or precise, so the trend is visible
before it crosses anything — the gate is the alarm, the printed number is the gauge.

**The parity gate is told about the split.** `check_ci_parity.py` requires `make loadtest`
present in the CI workflow (the coarse ceiling runs) and records that `CVAP_RUN_LOADTEST` is
deliberately ABSENT from it — so nobody "fixes parity" by adding the flaky precise gate to CI.

### The overshoot verdict: it does not exist, because the list is paginated

Measured at 10k assets / 50k findings, on the dev database:

| measurement                                | p95      | SLO    | coarse |
|--------------------------------------------|----------|--------|--------|
| asset list @10k                            | 2 ms     | 300 ms | 600 ms |
| finding list @50k, exposure 1.0            | 4 ms     | 500 ms | 1000 ms|
| finding list @50k, exposure 2.4            | 40 ms    | 500 ms | 1000 ms|
| observation ingest                         | 8800/sec | 5000   | 2500   |
| exposure-by-zone @50k, 1.0 / 2.4 (no SLO)  | 92 / 89 ms | —    | —      |

**The predicted overshoot did not materialise, and the reason is a design fact, not luck.** The
finding LIST is keyset-paginated at 50 rows, so its cost is bounded by the page, not by the
corpus or the exposure depth: the `count(DISTINCT zone_id)` runs for 50 findings whether there
are five thousand or five hundred thousand. Exposure depth is visible in it (4ms → 40ms from 1.0
to 2.4) but ten-fold under the SLO, because it is 50 subqueries either way.

The aggregation cost ADR-010 was worried about is real, but it lives in the **unpaginated**
`/v1/exposure` endpoint, which groups every `finding_exposure` row by zone. That is ~90ms at
both distributions and has no published SLO. So the answer to session 21's question is neither
"index gap" nor "inherent cost forcing an SLO revision": the SLO'd surface is paginated and does
not overshoot, and the surface that scales with exposure is a different, un-SLO'd endpoint that
is comfortably fast. **No SLO is revised, and no index is added**, because the measurement says
neither is warranted — which was the instruction: measure, then say which, rather than adjust the
SLO to fit.

If a future `/v1/exposure` grows an SLO, this is the endpoint to put a precise gate on, and its
cost model (scales with total exposure rows, not a page) is why it would need its own seed
distribution rather than reusing the list test's.

## Consequences

- CI fails on an order-of-magnitude performance regression and does not fail on runner noise.
- The precise SLO is enforced by the nightly job and by any developer who sets the flag; a
  regression that is real but sub-2× is caught there, a day later at worst, without muting.
- The printed numbers make the trend legible before the coarse ceiling is reached, which is the
  early warning a pass/fail gate cannot give on its own.
- `hashLoadPassword` in the load test now calls `credential.Hash` (ADR follows the extraction in
  the same session), so the seeded login credential cannot drift from the encoder the endpoint
  verifies against.

## Review trigger

When `/v1/exposure` (or any unpaginated aggregation) gets a published SLO, or when a real
deployment first produces the multi-vantage exposure distribution the 2.4 variant only
simulates — whichever comes first. At that point the exposure endpoint's cost stops being a
trend line and becomes a gate, and it needs its own seed shape.
