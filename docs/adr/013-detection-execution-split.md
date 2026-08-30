# ADR-013: Detection split — request-coupled at scan point, evidence-based at core

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 left it ambiguous whether detection logic runs at the Scan Point or at Core. That
ambiguity determines the entire rule update story: rules that run in the fleet must be
distributed across customer networks we do not control, to scan points running months-old
builds (ADR-022).

## Decision

Split on whether the test and the verdict are separable.

**At the Scan Point** — detection is *request-coupled*: the verdict depends on an interaction
that cannot be reconstructed from stored evidence. DAST active checks, timing-based
inference, protocol handshake behaviour, TLS negotiation quirks.

**At Core** — detection is *evidence-based*: the Scan Point reports what it observed, Core
decides what it means. Software versions, package inventories, configuration values, banners,
certificate contents, cloud resource state.

`RULE.execution_site` records which side a rule runs on, and a Scan Point receives rule packs
containing only scan-point rules. Nearly all rules fall in the second category.

A scan-point rule does **not** emit a finding. It emits an observation of
`observation_type: verdict` carrying `rule_id`, the outcome, and the request/response pair
that produced it (ADR-006). Core constructs the Finding from that verdict exactly as it does
from any other observation, so ADR-006 holds without exception. `verdict` is added to the
`OBSERVATION` type enum **in the ERD**; the wire field stays an open string and Core validates
against the ERD enum at ingest (ADR-006). The verdict payload should carry the rule pack
version that produced it, since a months-old scan point (ADR-022) emits months-old verdicts and
Core must know which rule version to attribute them to.

## Alternatives considered

**All detection at the Scan Point.** The conventional scanner design. Rejected because every
rule update becomes a fleet-wide distribution problem across networks we cannot observe, a
rule correction cannot retroactively fix historical findings, and a scan point on a
months-old build silently produces months-old verdicts.

**All detection at Core.** Attractive for the same reasons the split favours Core, and it is
where the majority of rules land anyway. Rejected because it is not physically possible for
request-coupled checks: a timing differential or a handshake quirk is a property of the
interaction, and no serialisable evidence reproduces it. Forcing those to Core would mean
shipping raw packet traces and re-deriving the verdict, which is both enormous and lossy.

**Run rules in both places and reconcile.** Doubles the implementation and creates
disagreement between two verdicts on the same evidence with no principled tie-break.

## Consequences

A rule update for the large majority of detection content is a Core deploy, not a fleet
rollout, and a rule correction retroactively fixes historical findings because the evidence
is retained (ADR-006). Confidence tuning happens centrally. The cost is result payload size —
Scan Points ship observations rather than verdicts, and evidence-based detection means
shipping the evidence — which is judged worth paying and is what ADR-015 and ADR-016 exist to
absorb. Rule authors must classify `execution_site` correctly; a request-coupled rule marked
`core` simply cannot work.

## Review trigger

Revisit if result payload volume becomes the binding constraint on scan throughput, or if a
class of detection appears that is evidence-based in principle but whose evidence is too
large to ship — in which case the answer is scan-point pre-summarisation, not moving the
verdict.
