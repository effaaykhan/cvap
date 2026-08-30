# ADR-004: Broker never exposed; dispatch service fronts it

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1's architecture showed the message queue fanning out directly to external, internal and
DMZ scan points. Combined with the outbound-only connection rule, that implies a broker
reachable from the internet — a contradiction that would have been baked into the wire
contract if left unresolved.

## Decision

The job broker is internal to Core and has no network path to any Scan Point. Scan Points
hold a long-lived authenticated stream to the Dispatch Service (ADR-005), which pulls from
the broker on their behalf. Scan Points never learn the broker's protocol, address, topic
names or credentials. The Dispatch Service is the only component that speaks both protocols.

## Alternatives considered

**Expose the broker directly with per-scan-point ACLs.** This is the v1 reading, and it is
the option that saves a component. Rejected because it puts a broker's full protocol surface
on the internet, makes the broker's authentication model the tenant isolation boundary, and
welds the wire contract to one broker's protocol — which would make ADR-003's deferred
substitution impossible without a fleet-wide upgrade across networks we do not control.

**Have Scan Points poll a REST endpoint instead of holding a stream.** Simpler, and it also
keeps the broker private. Rejected because it gives up server-initiated dispatch, forces a
latency-versus-load tradeoff on the poll interval, and makes the lease renewal and
backpressure signalling of ADR-012 and ADR-026 awkward — all of which the bidirectional
stream provides directly.

**Push jobs from Core to Scan Points.** Requires inbound connections into customer networks.
Ruled out by ADR-005.

## Consequences

The broker becomes a substitutable implementation detail, which is what makes ADR-003's
"defer NATS" defensible. A compromised Scan Point gains no read access to anything in Core
beyond its own job queue, bounding blast radius as the threat model requires. The cost is a
component that must be built and kept available: the Dispatch Service is on the critical path
for all scanning, so its availability is the fleet's availability.

## Review trigger

Revisit only if the Dispatch Service becomes a throughput bottleneck that cannot be resolved
by horizontal scaling. Exposing the broker is not on the table; the alternative would be
sharding dispatch, not removing the layer.
