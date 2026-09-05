---
name: safetydrive-budget-drift
description: SafetyDrive/runtimedrive harness (session 17) once skipped the rate/fragile clamp — FIXED same session by extracting clampToBudget, shared with job.budget(). Kept as the record of what to re-check.
metadata:
  type: project
---

## FIXED after the audit, same session (2026-09-05) — do NOT re-report

The rate/fragile clamp was extracted into `clampToBudget(clampInputs)` in
`internal/scanpoint/job.go`, and BOTH `job.budget()` and `SafetyDrive` now call
it. So the harness applies the identical ADR-024 ceilings as production: the rate
clamp, the fragile 10 pps rate cap, the fragile concurrency cap, and fragile/safe
probe suppression. `SafetyDrive` computes `AnyFragile` from its targets and passes
`FragileRate: 0` (unspecified → platform fragile ceiling). The only thing it still
does not reproduce is corpus resolution + the signed-pack `applyProbePolicy` (the
caller supplies probes), and the header now says so — a probe-corpus assertion
belongs in the engine-direct phases, not this seam. `go test ./internal/scanpoint`
(budget behaviour-preserving) and the scope gate both pass after the change.

The original finding, for the record:

`internal/scanpoint/safetydrive.go` (session 17, ADR-051 wire half) built
`engineBudget` inline from the `SafetyJob` fields and hands it straight to
`engineHost.start`. It does NOT call `job.budget()`, which is the production path
(`runtime.onAssignment` -> `runJob` -> `j.budget()`).

`job.budget()` is where ADR-024's rate/fragile enforcement lives: `clampCeiling`
(min of policy and platform ceiling), the fragile rate cap (10 pps), the fragile
concurrency cap (1), and fragile PROBE SUPPRESSION (a fragile target gets zero
probes regardless of mode). SafetyDrive applies none of these.

**Measured (2026-09-05)** with a throwaway `job.budget()` test: an intrusive job
with a fragile target, rate 100000, concurrency 9999 → production `budget()`
returned rate=10, concurrency=1, probes=0; SafetyDrive's inline `engineBudget`
kept rate=100000, concurrency=9999, probes=11. `engineHost.start`'s only probe
gate is `mode != intrusive`, so it ACCEPTS those 11 probes to a fragile device.

**Why:** SafetyDrive's own header claims it "runs ONE job through the exact path
the runtime runs" and "a packet it withholds is a packet the runtime withholds."
That is true for SCOPE (start -> authorise -> target.Matches + scope.Permits is
identical) but FALSE for rate/fragile/concurrency. So:
- the scope gate's verdict is valid (its cases use rate 50, safe, no fragile);
- a future rate/fragile wire case built on this harness would measure the harness,
  not production — a "proves nothing" trap the comment actively invites;
- the exported seam can drive the REAL engine to probe the lab fragile printer
  (10.10.0.40) at an unclamped rate — behaviour production structurally prevents.

Not a scope bypass and not a production-scanner defect (production runJob still
calls budget()). Rate/blast-radius fidelity gap in the test seam. Fix: have
SafetyDrive build its budget through `job.budget()` (or document loudly that it is
scope-only and must never be used to assert rate/fragile).

**How to apply:** if a later session adds a fragile/rate case to safety_scope.py
through runtimedrive, check it goes through budget() first. See
[[scanpoint_runtime_bypasses]] for the related terminal-path/rate history.
