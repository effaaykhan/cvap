# ADR-103: An open port is durable evidence; the rule engine does not see it yet

**Status:** Accepted
**Date:** 2026-09-24
**Follows:** ADR-016 (observations are ephemeral; what must outlive them is copied when it becomes
load-bearing), ADR-006 (what writes an asset from evidence), ADR-021 (safe mode), ADR-022
(`proto/` is frozen, additive-only).

## Context

A discovery scan of two real /24s produced **110 `port` observations across 25 assets**, and not one
of them reached the asset. `internal/correlate/correlate.go` opens its service loop with
`if o.Type != "service" { continue }`, so only the fingerprint engine's `service` observations
become rows. Discovery's ports stayed in `observations`, which ADR-016 defines as ephemeral and
prunes.

Three symptoms, one cause. The operator console shows 25 assets with nothing known about them —
`services` was empty while `assets` held 29 rows. The 14 active rules had no input and produced
zero findings. And a follow-up fingerprint scan re-walked its 246-port default list per host,
paying a connect timeout on every closed port, because nothing durable recorded which five or six
ports discovery had already found open.

An open port is the asset's attack surface. It is exactly the class ADR-016 says to copy out.

## Decision

**1. An unidentified open port is a `services` row.** It carries `port`, `protocol` and
`identification_method = 'discovery'`, with `service_name`, `product`, `version` and both
confidences NULL. Only `state = "open"` is promoted; `closed` and `filtered` are not evidence of a
service and must never create a row. No migration: on `services` only `port` and `protocol` are
`NOT NULL`, and `Upsert` already merges with `coalesce(nullif(excluded.X,''), services.X)`, so a
later fingerprint pass upgrades the row in place rather than duplicating it, and a later discovery
pass cannot erase a product the fingerprint pass established.

**2. Seen-only rows are NOT visible to the rule engine.** Rules continue to evaluate identified
services only. This is a measurement, not caution: in the scan above, **ports 2000 and 5060 were
reported open on 19 of 19 hosts** — the signature of a middlebox answering for the whole range, not
of nineteen SIP servers. Feeding that to the rules would manufacture findings from a network
artefact, and a finding an operator learns to dismiss is worse than no finding. A rule that wants
seen-only input opts in explicitly and argues for it.

**3. Scan results are read scan-scoped, from observations.** "What did this scan find" is answered
from the observations of that scan's tasks, not from assets, because an asset is not scan-scoped.
The consequence is deliberate and must be said on the screen: the scan view is a window onto
ephemeral data and empties as observations age out, while the asset's services are the durable
record.

## Alternatives considered

**A separate `open_ports` table.** Rejected. It would key on the same
`(tenant_id, asset_id, port, protocol)` as `services`, forcing every reader — the asset screen, the
rules, the exposure derivation — to join two tables and decide precedence between them. The
identity is the same thing; splitting it buys model purity and costs every consumer.

**Promoting ports and letting the rules see them.** Rejected on the measured false-positive rate
above. Revisit when service identification can distinguish a host answering from a middlebox
answering for it (B28).

**Leaving discovery output in observations and reading it live.** Rejected: it contradicts ADR-016
directly, and the data would vanish on prune while the asset it describes persists.

**Passing the discovered ports to the fingerprint task** so it probes six ports instead of 246.
Correct, and deliberately not here: `scan_tasks` carries only `task_target` with no params column,
and putting ports on the wire changes `proto/`, which ADR-022 freezes to additive-only changes.
Filed separately.

## Consequences

Easy: the asset screen's existing Services table fills after a discovery scan; an operator sees
which host has which port open without running a second scan type; a later fingerprint pass
enriches those rows rather than creating new ones.

Hard: `services` now means "a port we have seen", not "a service we identified", and every reader
must respect the distinction. The API exposes it so the console can render "open, unidentified"
rather than implying an identification nobody made.

Foreclosed for now: rules over bare ports, which is decision 2 and is reversible by a later ADR.

One implementation constraint this creates: `Upsert` coalesces the identification columns but
assigns `softmatch` and `solicited` unconditionally whenever the incoming sighting is newer
(`services.go:78-79`). A discovery pass that runs after a fingerprint pass would therefore reset
both. They must be preserved for a seen-only write, and that needs its own regression test — it is
the one clobber path the existing merge does not already close.

## Review trigger

Revisit decision 2 when B28 lands service identification that can tell a host answering from a
middlebox answering on its behalf; the 19-of-19 measurement is the thing to re-run. Revisit
decision 1 if a second unidentified-evidence kind (a responding but unreadable UDP port, an ARP-only
host) needs the same treatment and the marker stops carrying enough meaning.
