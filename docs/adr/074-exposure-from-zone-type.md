# ADR-074: The exposure term derives from zone type; the never-written column is dropped

**Status:** Accepted
**Date:** 2026-09-09

Resolves backlog #6, open since session 18. `finding_exposure.internet_reachable` was disclosed as a
weakness in ADR-059 (the Phase-3 sequence, "#6, consumed at P3.4") and again in ADR-069 (the priority
model itself, "The exposure input is weak, and the model says so"). Twice-disclosed and never decided
is not disclosure any more; it is a decision nobody made — and ADR-069's disclosure even misdescribed
the state, asserting "the authoritative column was dropped, the read derives from `zone_type`" when in
fact the column still existed and the read still consumed it. This ADR makes the decision, and makes
that claim true.

## Context

`internet_reachable` was added in migration 0011 as `boolean NOT NULL DEFAULT false`. Nothing ever
wrote it true — `SetExposure` inserts `(tenant_id, finding_id, zone_id, last_confirmed)` and omits it —
so every row has read `false` since the column existed. Session 18 found `finding_exposure` and
`scan_zones` answering "is this exposed?" two ways, and resolved to *derive from `zone_type` and leave
the column*. That was right for a read endpoint. It became wrong at P3.4, which made
`internet_reachable` the **second-strongest term in the shipping priority model** — the `1e8` weight,
directly below KEV. An always-false input there is not weak; it is **inert**: the exposure term never
discriminated, and the "derive from zone_type" the ADRs disclosed was never actually implemented — the
code read the dead column.

## Decision

**Drop the column; derive the exposure signal from the zone's type, which is written.** A finding
exposed from a zone whose `zone_type` is `external` or `dmz` is internet-reachable; the other types
(`internal`, `branch`, `cloud`, `mgmt`) are not. This is applied in both places that consumed the
column: the priority model's `1e8` term (`internal/store/findings.go` `List`) and the exposure detail
read (`findingExposures`), and it flows to the API `internet_reachable` field unchanged in shape but
now honest in value. Migration 0040 drops the column and its never-selective partial index.

### The ceiling, stated once instead of hedged three times

Zone type is an operator's **classification** of a network segment, not a measurement of whether a
specific asset can be reached from the internet. A finding in a segment an operator labelled `dmz` is
treated as internet-reachable; whether that host actually answers from outside is a **vantage-point
reachability determination the scanner could make and does not** — a probe from an external vantage,
or a route/ACL analysis. So the exposure term is now *real* (it derives from written data and
discriminates) but *coarse* (segment-level, operator-declared). That ceiling is stated here, once, in
a decision — not disclosed again in the next model that reads it. When a real reachability
determination is built, it replaces the zone-type derivation at these two call sites and the ceiling
lifts; nothing else in the model changes, because the model already consumes a single boolean.

### `auth_required` is the sibling left standing, deliberately

`finding_exposure.auth_required` is the same never-written shape. It is **not** dropped, because it is
display-only and not a term in the priority model, so it has not accrued the "an input nobody wrote"
problem that forced this decision. Its natural writer is Phase 4's credentialed assessment (whether a
finding sits behind authentication is something a credentialed probe learns). Recorded here so it is a
known, decided deferral rather than a fourth silent disclosure.

## Consequences

- Migration 0040 drops `internet_reachable` and `finding_exposure_internet_idx`; reversible (the down
  restores both, as dead as they were). No RLS or grant change — a column drop on an already-scoped
  table.
- The priority model's exposure term discriminates for the first time: a finding in an external/dmz
  zone now clears the `1e8` boundary, ranking above an internal-only finding of equal KEV/EPSS/CVSS.
- The acceptance and read tests that seed a DMZ zone now see `internet_reachable = true` derived,
  where before they saw the stored `false` regardless — the derivation is exercised, not asserted.
- ADR-059 and ADR-069 disclosed this gap as a live weakness (ADR-069 even misdescribing the state);
  they are frozen and unedited, and this ADR is where the weakness stops being disclosed and starts
  being a decision. The next model that reads exposure inherits a real term with a stated ceiling,
  not a hedge.
