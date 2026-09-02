---
name: add-scan-engine
description: Procedure for adding a new scan engine behind the capability contract. Use when creating a new engine under internal/engines.
paths:
  - internal/engines/**
  - internal/scanpoint/**
---

# Adding a scan engine

Engines are the extension point. The Control Plane must not change when one is added.

## Contract

An engine implements the engine interface in `internal/scanpoint/engine.go` and nothing more:

- Declares a capability name and version, surfaced in the connect handshake. It is a
  **ceiling, never a grant**: it can only narrow what Core dispatches, and Core takes
  authorisation from its own records keyed on the authenticated identity.
- Runs as a **separate process** hosted by the runtime (ADR-027), not in-process.
- Accepts **resolved, pre-authorised targets** and returns observations.
- Emits **observations only**. Never assets, never findings.
- **Holds no scope data.** No allowlist, no exclusion list, no CIDR arithmetic. Scope
  enforcement is at exactly two sites — Core at planning and the runtime on the send path —
  and never in an engine (ADR-024, ADR-027). If an engine needs to know whether an address is
  in scope, the design is wrong: it should be asking the runtime, not deciding. Anything
  discovered mid-scan — a redirect, a DNS answer, a referenced host — goes back to the runtime
  for authorisation before the engine may touch it.
- **Stays inside the rate slice the runtime allocates**, and reports actual send counts so the
  runtime can reclaim what is unused. An engine does not read the platform ceiling and does not
  coordinate with other engines: the aggregate is bounded by the runtime's allocation, not by
  cooperation (ADR-024, ADR-027).
- **Never receives raw credential material.** The runtime establishes the authenticated session
  and passes a session handle or a short-lived derived token (ADR-020). An engine that crashes
  cannot leak what it never held.
- Honours context cancellation within seconds, so the kill switch and lease loss work. The
  runtime sends `SIGTERM` then `SIGKILL` after a short grace.
- Holds no state between tasks and writes nothing to disk.

## Steps

1. Register the capability so Core can gate dispatch on it. Old scan points must not
   receive jobs for an engine they do not have.
2. Implement against the interface. Keep protocol parsing bounded — engines read hostile
   input by design, so every read needs a limit and a timeout.
3. Add lab targets exercising the engine, and golden corpus entries with expected results.
4. Wire the engine into the scan point's engine host.
5. `internal/engines/import_policy_test.go` forbids `net`, `net/http`, `os/exec`, `syscall`
   and friends in every package under `internal/engines`, with an allowlist that is empty
   today. An engine that genuinely sends packets adds an entry there **with an ADR** saying
   why and how ADR-024's ceilings bind it. Deleting the guard is the other way to make the
   build pass, and it is the wrong one.
6. Run `scan-safety-auditor` before merging. This is not optional for anything that sends packets.

## Do not

- Import control plane packages from an engine.
- Reach the database from an engine.
- Add a job type to the protocol without a capability gate.
- Assume the scan point can reach anything the Core can.
- **Put a scope check in an engine.** This file used to say "re-checks every target against
  the exclusion list before sending. Core checked already; check again", which predates
  ADR-027 and is now wrong. Duplication is deliberate and it is between Core and the
  **runtime**; a third site in the engine breaks the property `make safety` asserts, which is
  that enforcement happens at exactly two places regardless of how many engines exist or what
  language they are written in.
