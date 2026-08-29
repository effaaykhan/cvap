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

- Declares a capability name and version, surfaced in the connect handshake.
- Accepts a task plus `ScanConstraints`, returns observations.
- Emits **observations only**. Never assets, never findings.
- Respects the rate ceilings in the constraints on the actual send path, not just at entry.
- Re-checks every target against the exclusion list before sending. Core checked already;
  check again.
- Honours context cancellation within seconds, so the kill switch and lease loss work.
- Holds no state between tasks and writes nothing to disk.

## Steps

1. Register the capability so Core can gate dispatch on it. Old scan points must not
   receive jobs for an engine they do not have.
2. Implement against the interface. Keep protocol parsing bounded — engines read hostile
   input by design, so every read needs a limit and a timeout.
3. Add lab targets exercising the engine, and golden corpus entries with expected results.
4. Wire the engine into the scan point's engine host.
5. Run `scan-safety-auditor` before merging. This is not optional for anything that sends packets.

## Do not

- Import control plane packages from an engine.
- Reach the database from an engine.
- Add a job type to the protocol without a capability gate.
- Assume the scan point can reach anything the Core can.
