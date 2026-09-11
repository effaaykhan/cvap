# ADR-090: A credentialed observation resolves family and release itself, ahead of the inferred-family gate

**Status:** Accepted
**Date:** 2026-09-11
**Implements:** the remedy ADR-089 named and left for a scoped increment. ADR-089 is frozen; this records
the decision and the change, and closes ADR-089's review trigger.

ADR-089 measured that ADR-077's release-precedence rule, though correct as a unit, never fired on the
first real credentialed observation: `credentialedRelease` sat inside `deriveRelease`, which `resolveHost`
calls only under `family != ""`, and a credentialed `package` observation correlates in a sweep with no
service observations, so no inferred family, so the rule was never reached. ADR-089 named three remedies.
The operator chose the third and stated the principle sharply:

> `/etc/os-release` **is** ground-truth family. Gating it behind a service-derived family inverts the
> confidence ordering — the weaker, inferred signal gates the stronger, exact one. That is backwards
> regardless of the sweep mechanics.

## Decision

A credentialed `package` observation now resolves **both** family and release by itself, at confidence
1.0, ahead of and independent of the service-inferred attribution.

- The `package` payload carries `family` (the os-release `ID`, e.g. `ubuntu`) alongside the release it
  already carried. The credhost engine populates it from `read.Release.ID`.
- `resolveHost` calls `credentialedAttribution(h)` **before** the `family != ""` band-vote gate. When a
  usable credentialed observation is present (os-release source, non-empty release AND family), it writes
  the family via `SetAttribution` and the release via `SetRelease`, both at 1.0, with provenance recording
  each outranked the inferred signal. The band vote runs only when there is no credentialed observation.
- The exact-read branch was **removed from `deriveRelease`**, which is now the band-vote inference only.
  Release resolution is one path per source, not two: the thing that made ADR-077 unreachable was exactly
  that its branch lived behind `deriveRelease`'s own caller-gate.

A credentialed payload that carries no `family` (pre-ADR-090, or the dormant/instrument shapes) is not a
self-sufficient attribution and falls through to band voting unchanged — the change is backward-safe.

## Why the confidence ordering is the real argument, not the sweep

The sweep mechanics (a package-only host group) are how the bug *surfaced*, but they are not why the fix
is right. Even on a host whose services *did* yield a family, gating the exact `/etc/os-release` read
behind that inferred family would be backwards: the inferred family is a guess with a confidence below 1,
and the exact read is ground truth. An exact signal must never be conditional on a weaker inferred one.
Fixing only the sweep (re-reading resolved observations into the group) would have left that inversion
standing; lifting the exact read ahead of the gate removes it at the root.

## Proving reachability, not just correctness

ADR-089's lesson (and §9 5.12) is that a passing *unit* test of `credentialedRelease` never proved the
rule would *run* — it proved it was correct if run. So the acceptance for this change is an **integration**
test, not another unit test: `TestCredentialedReleaseReachesResolutionWithoutInferredFamily` drives a real
correlator sweep over a host whose services yield no family plus a credentialed `package` observation, and
asserts the release resolves to the exact value at confidence 1.0. Under the pre-ADR-090 code that host's
release was NULL (the gate skipped resolution); the test now pins that it is resolved. `credentialedRelease`
became `credentialedAttribution`, and its unit tests move with it — but they are no longer the proof.

## Consequences

- ADR-077's rule is **live**, not dormant: a credentialed host's release now reads 1.0 `package_manager`
  provenance, not the band-vote 0.8. The understatement ADR-089 flagged as a latent limitation is closed.
- `packagePayload` gained `family` (additive, `omitempty`) in both the correlator and the engine copy. No
  proto change — the `package` observation payload is JSON, not a wire message.
- The supersession lifecycle (S41) is unaffected: `evaluateCredentialed` was already ungated and closed
  the `.146` sixteen; this change makes the *release* on the same asset finally reflect the exact read.
- Review trigger: the fleet-path re-run (the dispatch-grant + enginehost + `EngineForScanType` increment),
  where a credentialed observation arrives through ingest for real and this resolution runs on live data —
  the point at which ADR-088's "unexercised end-to-end" is finally discharged.
