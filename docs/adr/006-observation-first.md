# ADR-006: Observation-first — scan points never write assets or findings

**Status:** Accepted
**Date:** 2026-08-30

## Context

If Scan Points write assets and findings directly, the reasoning that produced them happens
in a distributed fleet running months-old builds, and the evidence for it is discarded once
the row is written. Asset merges then become irreversible, correlation bugs can only be fixed
by re-scanning, and no finding can answer "why does the system believe this" — the first
question every analyst asks about a finding they doubt.

## Decision

Scan Points emit **Observations**: immutable, timestamped records of what was seen, by which
Scan Point, from which vantage zone, with what confidence. Assets, services, software
components and findings are derived from observations by Core. No Scan Point writes to the
asset or finding tables, directly or transitively.

`observation_type` is `host | port | service | banner | package | config | verdict`. The
**`verdict`** type carries the outcome of a request-coupled rule that could only be evaluated
at the Scan Point (ADR-013): it holds `rule_id`, the outcome, and the request/response pair
that produced it. A verdict is still an observation — immutable, vantage-tagged, evidence-
bearing — and **Core still constructs the Finding from it**, applying dedup keys (ADR-010),
exposure (ADR-008) and confidence centrally. A Scan Point reporting a verdict is reporting
what it saw, not writing a finding.

**The type set is a closed enum in the ERD and an open string on the wire.** This is
deliberate, not an oversight: engines are extensible by design (ADR-027), and a closed wire
enum would make every new observation type a protocol change. Producer and consumer agreement
is enforced by **Core validating the incoming value against the ERD enum at ingest**, returning
`REJECTED_MALFORMED` (ADR-026) for an unknown type. Do **not** tighten `observation_type` to a
proto enum later — that is precisely the semantic change to an existing field that ADR-022
forbids.

## Alternatives considered

**Scan Points write assets and findings directly.** The obvious design and the v1 reading.
Rejected on four counts at once: merges become irreversible because the justifying evidence
is gone, multi-vantage-point exposure cannot be reconstructed, a correlation fix requires
re-scanning the estate, and findings are unexplainable to the analyst disputing them.

**Scan Points write findings but not assets.** A middle path that keeps identity resolution
central. Rejected because it puts detection logic in the fleet, which forces every rule
correction to become a fleet-wide distribution problem across networks we do not control —
and it means a corrected rule cannot retroactively fix historical findings. See ADR-013.

**Let request-coupled rules write findings directly, since their verdict cannot be re-derived
at Core anyway.** The tempting exception, and rejected: the verdict is not the finding. Dedup
keying, exposure aggregation across vantage points, confidence calibration and reopen
semantics are all central concerns that a Scan Point has no basis to decide. Modelling the
verdict as an observation keeps the one thing the Scan Point genuinely knows — what happened
in that interaction — in the fleet, and everything else at Core.

**Keep observations as a transient ingest buffer, discarded after derivation.** Cheaper to
store. Rejected because the retained evidence is precisely what makes merges reversible and
correlation re-runnable; discarding it gives up the benefit while keeping the plumbing.

## Consequences

Correlation can be re-run over history after fixing a bug, without touching a customer's
network. Every finding traces to the observation that produced it. Exposure across vantage
points falls out of the data model rather than being assembled. The costs are real: an extra
entity and derivation stage on every path, storage growth concentrated in one table (handled
by ADR-016), and the fact that the UI must never show a raw observation as though it were a
confirmed asset.

## Review trigger

None expected — this is the load-bearing decision that ADR-007, ADR-008, ADR-010 and ADR-013
all rest on. Revisit only if derivation latency makes near-real-time inventory unachievable,
and then by optimising derivation, not by letting Scan Points write.
