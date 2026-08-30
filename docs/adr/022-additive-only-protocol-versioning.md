# ADR-022: Protocol versioning is additive-only within a major version

**Status:** Accepted
**Date:** 2026-08-30

## Context

Version skew is the default state, not an edge case. Scan Points live in customer networks
behind change control boards and will run months-old builds. Core will be deployed
continuously. Any protocol change that a months-old scan point cannot tolerate is a
fleet-wide outage in networks we cannot observe or fix.

## Decision

The Scan Point protocol is explicitly versioned and **additive-only within a major version**:
no field removals, no field renumbering, no semantic changes to existing fields. Scan Points
declare their capabilities *and* engine versions on connect, and Core never dispatches a job
type or rule format the scan point cannot execute — `Capability` therefore declares
`rule_format_version` alongside engine version. A **minimum supported version window** is
published and enforced with a clear operator-facing error rather than mysterious failure: Core
answers `Hello` with a `ServerHello` carrying the accepted version, the minimum supported
version and any deprecation notice, rather than closing the stream with a bare status code.
`SCAN_POINT.protocol_version` and `SCAN_POINT_CAPABILITY.engine_version` record what each
scan point can actually do. Self-update is staged and automatic in SaaS, optional on-prem,
because change control boards exist. `proto/` is a frozen contract: changes are reviewed
against this ADR.

## Alternatives considered

**Require fleet-wide upgrade before a breaking protocol change.** The implicit default if
this is not decided. Rejected: we do not control when a customer upgrades, an on-prem
customer may be air-gapped, and the failure mode is a scan point that silently stops working
inside a network we cannot reach.

**Version negotiation without the additive-only rule — support N and N-1 fully.** Rejected:
it means maintaining two implementations of every changed message and knowing when the last
old scan point disappeared, which we cannot know. Additive-only makes old scan points work by
construction rather than by our remembering to keep the compatibility path.

**Capability negotiation only, without protocol versioning.** Covers engine differences but
not wire format changes, so it does not address the case that actually breaks a stream.

**No minimum version window — support every build forever.** Rejected: it makes every
deprecation impossible and accumulates compatibility debt without bound. A published window
with a clear error is the honest version.

## Consequences

An old scan point keeps working and simply does not receive job types it cannot execute,
which is a degraded but comprehensible state an operator can act on. Core can deploy
continuously. The costs are permanent: deprecated fields stay in the contract, field numbers
are never reused, mistakes in the wire format are effectively frozen until the next major
version, and Core carries the branching to serve capability-poor scan points. This is why
`proto/` is frozen and reviewed rather than edited casually.

## Review trigger

A major version bump — the only occasion on which removals are permitted, and one requiring a
deliberate migration plan for the fleet. Revisit the supported version window when field data
shows how far behind customer scan points actually run.
