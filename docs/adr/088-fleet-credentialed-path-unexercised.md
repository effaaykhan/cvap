# ADR-088: The fleet credentialed path is unexercised end-to-end; its acceptance is a real-pipeline refutation

**Status:** Accepted
**Date:** 2026-09-11
**Companion to:** ADR-087 (which is frozen; this states its honest-scope note more sharply, as the
operator directed, rather than editing it).

ADR-087 records that Session 40's credentialed numbers were measured via the `cvap-credscan`
instrument, whose matching is identical to the fleet correlation's, so the numbers are
path-independent. That is true and worth stating. This states the other half equally plainly, so the
record cannot be read as more than it is.

## What has not happened

**The fleet path has never produced a credentialed finding end-to-end.** No `cvap-engine-credhost`
has emitted a `package` observation; no `package` observation has reached correlation; no credentialed
finding has been written by the pipeline. Everything credentialed this session — the version reads,
the FP numbers, the `.146` 16→0, the rpm result — came from the operator instrument, which computes
the credentialed finding set with the same exact-version matching but does not run it through
dispatch, the engine wire contract, correlation, or the finding lifecycle.

Two consequences follow, and both must be stated:

- **ADR-077's release-precedence rule is still dormant.** It fires when a credentialed `package`
  observation reaches `deriveRelease`; none ever has, so the rule has never executed against real
  data. Built and unit-tested (ADR-077), never exercised.
- **The supersession lifecycle is spec'd, not exercised** (the credentialed-vs-inferred spec):
  `superseded_by_credentialed` / `refuted_by_credentialed` are proposed finding-lifecycle states, not
  implemented ones. No inferred finding has been closed by a credentialed one.

## The next increment's acceptance

The fleet credentialed engine is accepted when **`.146`'s sixteen unauthenticated OpenSSH findings
actually close as `refuted_by_credentialed` through the real pipeline** — the credhost engine emits
`package` observations, correlation consumes them (activating ADR-077), the credentialed finding set
is produced, and the supersession lifecycle closes the sixteen inferred candidates as refuted —
**not** the instrument computing a zero. Until that run, the capability is unproven as a *system*,
however correct the matching is as a *unit*.

That distinction is itself §9's 5.11 (the EVR bug): a proven unit is not a proven system, and an
instrument that shares the matching is an oracle of the matching, not of the pipeline. The 16→0 is a
correct number today and an unclosed loop until the pipeline draws it.
