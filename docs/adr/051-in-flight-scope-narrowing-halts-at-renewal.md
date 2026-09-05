# ADR-051: A scope narrowing reaches an in-flight job at its next lease renewal

**Status:** Accepted
**Date:** 2026-09-05

## Context

ADR-024 duplicates scope enforcement at two sites — Core at planning, the scan point on the
send path — and neither trusts the other. Both sites read the scope that was frozen onto the
`JobAssignment` when the job was dispatched: Core's planning check runs at claim time in
`offerWork`, and the scan point re-checks each target against the `ScanConstraints` it received
(`engineHost.authorise`). Nothing re-reads the policy while a job runs.

So an operator who **narrows** a policy's scope under a running scan — adds an exclusion,
removes an allow, revokes `authorization_verified` — reaches no in-flight task. The change
takes effect only for the next job claimed under that policy. A scan-safety audit recorded this
as a standing gap: *"constraints are computed at claim time and never re-pushed … a closing
window now does, through the renewal refusal, and that is the only dimension with a mid-scan
lever."*

That is the same asymmetry ADR-024 rejected for the time dimension and then closed:
`windowClosedForJob` gives the maintenance window a second, in-flight enforcement site by
refusing the lease renewal of a job whose window has shut. The target dimension had one site
for in-flight work — the frozen copy — and the frozen copy cannot narrow. The §6.3 safety
suite needs a defined, testable answer to "scope changed mid-scan, tasks in flight," and there
was none to test.

The kill switch and per-scan cancellation (ADR-024 control 4) exist, but they are a **coarse
operator action**, not a consequence of editing scope: an operator who removes one host from a
policy expects the scan to stop touching that host, not to have to separately hunt down and
cancel the whole scan. Leaving narrowing inert until a manual cancel is the operator surprise a
safety control should not have.

## Decision

**A scope narrowing halts the affected in-flight job at its next lease renewal, whole-job, by
refusing the renewal.** The target dimension gains the second in-flight enforcement site the
time dimension already has, and by the same mechanism.

`scopeNarrowedForJob` runs in `onLeaseRenewal`, beside `windowClosedForJob`. It re-reads the
job's policy scope rules **as they are now**, re-derives the allow/exclusion lists through the
same `scopePlan` the dispatch path uses, and re-checks every one of the job's task targets
through the same `target.Matches` + `scope.Permits` both enforcement sites already call. If any
target is no longer permitted, the renewal is refused with `LEASE_STATE_LOST` and an
operator-facing reason naming the target. Invariant 8 and ADR-012 turn a refused renewal into a
runtime self-abort with credential zeroisation — a stronger stop than asking, and one that does
not depend on a wedged runtime cooperating.

Three properties are load-bearing and each mirrors `windowClosedForJob`:

- **Whole-job, not per-target.** One target falling out of scope halts the whole job. Dropping
  only the newly-excluded targets and letting the scan continue would require pushing new
  `ScanConstraints` to a running engine and re-authorising its queued work — a new wire message,
  an ADR-022 change, and runtime code that does not exist. Halting the job is fail-safe, needs
  no proto change, and is exactly what the window lever already does.

- **Fail-OPEN on a read error.** A database blip must not self-abort every in-flight job and
  zeroise the fleet's credentials over a transient. The start-side check (`offerWork`) fails
  closed by *withholding* work; this in-flight check fails open by leaving the lease alone until
  the next renewal, when it runs again. A policy that cannot be read keeps its lease.

- **An unexpressible scope is left to the start side.** If the policy's rules no longer pass
  `scopePlan` (a `tag` deny, an invalid CIDR), the running job is left alone — `offerWork`
  already refuses such a policy by name at the next claim, and revoking an in-flight lease for
  a planning defect would halt work that was authorised when it started.

The re-check reads the **live** policy and the job's **stored** task targets, and re-runs the
one matcher both sites share. It introduces no third evaluation of scope: a divergence between
this check and the two enforcement sites would be the same silent drift `internal/scope` exists
to prevent, which is why it calls `scopePlan`, `target.Matches` and `scope.Permits` rather than
a paraphrase of them.

## Alternatives considered

**Leave it: cancellation is the only in-flight lever.** No code, and defensible on the letter
of ADR-024 — scope is frozen at plan time and the platform's guarantee is only about what was
authorised then. Rejected: it makes "narrow the scope" a no-op on the very scan the operator is
watching, and the natural repair (cancel the whole scan) is both blunter than intended and easy
to forget. A safety control that requires a second, unrelated action to take effect is one
operators will believe they used when they did not.

**Push narrowed `ScanConstraints` to the running job and re-authorise per task.** The precise
answer: the scan continues, only the excluded targets stop. Rejected for this session as
disproportionate — it is a `proto/` change (ADR-022), a new runtime re-authorisation path, and
new failure modes (a push that races the engine's next send), for a refinement over a fail-safe
whole-job halt. Recorded as the review trigger below; when a customer needs a long scan to
survive a one-host exclusion, this is the design to reach for.

**Re-check on a timer rather than at renewal.** A dedicated sweep re-evaluating in-flight scope
independent of the lease cadence. Rejected: the renewal is already the heartbeat the window
lever rides, its cadence is bounded and known, and a second timer is a second place for the
answer to drift from the lease's own accounting.

**Re-check at the scan point instead of Core.** Symmetric to ADR-024's rejected "enforce at the
scan point only": the scan point cannot read the policy, and shipping the live policy to it is
the wire push this ADR defers. The renewal already crosses Core, which holds the policy, so the
check belongs where the data is.

## Consequences

Narrowing a policy's scope now halts every affected in-flight job within one renewal interval,
whole-job, with the target named in the audit trail and credentials zeroised on abort. The
target dimension and the time dimension now behave the same way in flight, which is one fewer
asymmetry for an operator to learn.

The cost is bluntness: excluding one host from a policy stops every running scan under it that
touches that host, not just that host's traffic. For a large estate mid-scan that is a real
re-run cost, and the honest answer is the per-task push named above rather than pretending the
whole-job halt is free.

The re-check adds one policy read and one task read per renewal for jobs whose policy is being
edited — in the common case where scope has not changed, it re-derives the same lists and finds
every target still in scope, at the cost of those two reads on each renewal. If that cost is
measurable at the renewal rate, the re-check can be gated on a policy-version bump; it is not
today, because correctness before optimisation is the right order for a scope control.

Measured, not asserted: the §6.3 safety suite's scope-changed-mid-scan case drives a job in
flight against a routable target, narrows the policy scope under it, and asserts at the wire
that egress to the now-excluded host stops within one renewal — the first time this lever is
exercised on a wire rather than in a unit test.

## Review trigger

A design partner whose scans are long enough that a one-host exclusion mid-scan cannot afford
to halt the whole job. That is the point at which the per-task scope push — new
`ScanConstraints` to a running engine, re-authorisation of queued targets — earns its proto
change and its runtime complexity, and this decision's whole-job halt becomes the fallback for
the unexpressible cases rather than the rule.
