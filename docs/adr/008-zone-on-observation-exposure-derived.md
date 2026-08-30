# ADR-008: Zone is a property of observations; exposure is derived

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 put `zone` on the asset table. Assets move: a laptop is on the corporate LAN, then home
wifi, then a hotel network; a cloud instance changes subnets. A stored zone is therefore
wrong shortly after it is written, and it is wrong in the specific way that produces
incorrect exposure reporting — the number executives read first.

## Decision

There is no `zone` column on `ASSET`. Zone is an attribute of the **observation**: what has
a vantage point is the act of seeing, not the thing seen. Exposure is computed — which
vantage points can currently see this asset, and what does each one see — and materialised
per finding in `FINDING_EXPOSURE`. Addresses are likewise time-bounded:
`ASSET_ADDRESS.valid_from` / `valid_to`, with current state queried as `valid_to IS NULL`.

## Alternatives considered

**Keep `zone` on the asset and update it on each scan.** Rejected: it is last-writer-wins
across vantage points, so an asset seen from both the DMZ and the internal network gets
whichever scan finished last. It also cannot represent the true answer, which is that the
asset is visible from several zones at once.

**Store a set of zones on the asset.** Closer to correct, but it is a denormalised cache of
observation data with no timestamps, no evidence, and no way to age out a zone the asset has
left. If it is derived anyway, derive it from the source.

**Compute exposure at query time from raw observations, with no `FINDING_EXPOSURE` rows.**
Always current, but it makes every dashboard query scan the largest partitioned table in the
system, and exposure is an input to the risk score (architecture-v2 §14) which
must be stable enough to sort by.

## Consequences

Multi-vantage-point exposure — the product's differentiator — falls out of the data model
rather than being bolted on, and it is the same data v1 already committed to collecting.
The same issue seen from two zones becomes one finding with two exposures (ADR-010) instead
of inflating the critical count. The cost is that "what zone is this asset in" is no longer a
column read: it is a derivation with a freshness characteristic that the UI must present
honestly, and stale exposure after a network change is a real failure mode to design for.

## Review trigger

Revisit if exposure derivation cannot keep up with ingest such that dashboards show
materially stale exposure — the fix being incremental derivation, not a stored zone column.
