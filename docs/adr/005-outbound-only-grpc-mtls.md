# ADR-005: Scan point transport posture: outbound-only, scan-point-initiated mTLS

**Status:** Accepted
**Date:** 2026-08-30

## Context

Scan Points sit inside customer networks — corporate LANs, DMZs, branch offices, cloud VPCs.
Any design requiring Core to open a connection into those networks requires the customer to
punch inbound holes in their firewall for a vendor, which is both a security objection and a
procurement obstacle raised on the first call.

## Decision

This ADR fixes the **transport posture**, not a single connection. The Scan Point always
initiates: outbound TLS 1.3 with mutual authentication to Core. Core never opens an inbound
connection to a Scan Point, in any deployment mode, for any reason.

Four Core services run over that posture, each scan-point-initiated:

- **Enrollment** — token exchanged once for a client certificate, and later rotation
  (ADR-018).
- **Dispatch** — a long-lived gRPC bidirectional stream carrying jobs, leases, credentials,
  capability negotiation, cancellation and the kill switch (ADR-004).
- **Ingest** — chunked, idempotent result submission with per-chunk acks and its own flow
  control. **Results go here, not on the dispatch stream** (ADR-026).
- **RulePacks** — bulk download of signed rule packs and knowledge bundles (ADR-019). The
  dispatch stream carries only a *notification* that a new pack exists.

Separating them is what keeps bulk transfer — a long result upload, a multi-MB rule pack —
from head-of-line blocking job dispatch, and lets ingest scale independently.

## Alternatives considered

**Core-initiated dispatch, or a hybrid where Core calls back for urgent work.** Rejected: a
hybrid is the same firewall exception as the pure inbound design, since the customer must
open the port either way. "Only sometimes" is not an argument that survives a security
review.

**Outbound long-polling HTTP instead of a persistent stream.** Works through the same
firewall rules and is simpler to debug. Rejected because it makes server-initiated messages
— lease revocation, immediate cancellation, the kill switch in ADR-024 — arrive only at poll
boundaries, when the entire value of those controls is that they are immediate.

**A VPN or reverse tunnel (WireGuard, SSH) carrying an ordinary RPC protocol.** Pushes the
problem into a component the customer must also operate, and grants broader network reach
than the job stream needs. mTLS on the application connection gives per-scan-point identity
directly, usable in the audit log.

**One connection carrying every service, including results and rule packs.** Fewer sockets and
one authentication handshake. Rejected: it couples bulk transfer to dispatch liveness, so a
multi-megabyte upload or rule pack download is interrupted by an ordinary dispatch reconnect
and head-of-line blocks every job assignment behind it, and it makes independent scaling of
ingest impossible. The posture is shared; the connections are not.

## Consequences

Deployment requires only outbound 443-style egress to Core, which nearly every customer
already permits, and one firewall rule covers every service because they share a destination
and a posture. The certificate fingerprint becomes the Scan Point's identity for authorization
and audit (ADR-018), and central revocation is immediate. In exchange, Core must hold and
manage many long-lived dispatch connections alongside ingest load; connection loss becomes a
first-class state the lease protocol has to handle (ADR-012); and debugging a stuck stream
inside a network we cannot observe requires the diagnostics bundle to exist from Phase 1.

## Review trigger

None expected. This is a load-bearing constraint that customers select us on; revisit only if
a deployment target makes outbound egress impossible, in which case the answer is a
customer-side relay, not an inbound connection.
