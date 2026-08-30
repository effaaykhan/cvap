# ADR-024: Scan blast-radius controls

**Status:** Accepted
**Date:** 2026-08-30

## Context

ADR-021 constrains what a check does to a target it is authorised to touch. It says nothing
about touching the wrong target, or touching the right target too hard. Aggressive scanning
knocks over printers, embedded devices, older network gear, and notoriously fragile SCADA and
medical devices — and a scan that reaches outside the authorised scope is an incident
regardless of how safe the individual check was.

## Decision

Four controls, all operational rather than rule-level:

1. **Scope enforcement is duplicated.** Target allowlists and exclusion lists — with
   exclusions taking precedence over allows — are validated at Core during planning
   (`POLICY_SCOPE_RULE` with CIDR and hostname validation, per-scan authorization recorded on
   `SCAN_TARGET.authorization_verified`) **and again at the Scan Point before packets leave**.
   Neither side trusts the other.
2. **Rate ceilings are lower-only.** The platform sets a default maximum rate.
   A `SCAN_POLICY` may **lower** it and may never **raise** it. Rate limiting is adaptive
   during execution.
3. **`fragile` is a first-class asset attribute.** It suppresses aggressive checks and caps
   rate regardless of what the policy permits.
4. **A hard global kill switch**, alongside per-scan immediate cancellation, reaching the
   fleet over the existing bidirectional stream (ADR-005).

Rate control is a correctness feature, not politeness.

**This ADR is the authority for the platform defaults.** They are recorded here and referenced
elsewhere; `docs/execution-plan.md` and the `cvap-invariants` skill point at this table rather
than restating the numbers, because three copies is how numbers drift.

| Limit | Default | Policy may |
|---|---|---|
| Rate per scan point | 1,000 pps | lower only |
| Rate per target host | 50 pps | lower only |
| Rate against `fragile` assets | 10 pps | lower only |
| Connection timeout | 3 s | adjust |
| Concurrent connections per target | 20 | lower only |
| Kill switch propagation | within 10 s | not adjustable |

Every one of these reaches the Scan Point on the wire — `allowed_targets`, `exclusions`,
`fragile_rate_pps`, `max_concurrent_per_target` and `connect_timeout_ms` on `ScanConstraints`,
and `fragile` per `Task`, since it is a Core-held asset attribute the Scan Point cannot derive.
A ceiling that does not reach the component sending packets is decorative. The kill switch is
acknowledged with `KillAck`, because a 10-second bound Core cannot measure is not a control.

## Alternatives considered

**Enforce scope at Core only.** The scan point already receives only in-scope jobs, so this
looks sufficient. Rejected: it makes a single planning bug, a stale policy on an old scan
point, or a compromised dispatch path into out-of-scope traffic in a customer's network, with
no second line of defence. The duplicated check costs little and is what `make safety` exists
to verify.

**Enforce at the Scan Point only.** Rejected symmetrically: scan points run months-old builds
(ADR-022), so Core cannot rely on their enforcement being current.

**Let policies raise the rate ceiling for customers who ask.** They will ask, usually to fit a
scan inside a maintenance window. Rejected: the ceiling exists because of devices the customer
has forgotten are on the network, and the damage lands on us regardless of who set the number.
Lower-only keeps the platform's guarantee intact.

**Treat fragility as a policy exclusion rather than an asset attribute.** Rejected: fragility
belongs to the device, not to the scan, so it must apply to every scan that ever touches it —
including one written by someone who has never heard of that device.

**Rely on adaptive rate limiting alone, with no hard ceiling.** Adaptation reacts after
observing degradation; some devices fail before the first feedback signal arrives.

## Consequences

Out-of-scope traffic requires two independent failures, and the safety suite can assert both
paths. Fragile estates become scannable rather than off-limits. The costs are direct: scan
duration is bounded by the ceiling, so large estates may not fit a narrow maintenance window
and the honest answer is more scan points rather than more speed; scope rules must be
evaluated identically on both sides or valid scans are silently dropped; and `fragile` needs a
population path — inventory alone will not set it.

## Review trigger

When a design partner's estate cannot be scanned inside their window at the current ceiling,
or when a device class is damaged at or below the fragile rate.
