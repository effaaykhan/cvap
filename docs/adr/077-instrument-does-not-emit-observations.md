# ADR-077: The validation instrument does not emit observations; the release-precedence rule is built dormant

**Status:** Accepted
**Date:** 2026-09-10

Refines ADR-076. Building the credentialed validation instrument (Session 39) reached the point
where ADR-076 said it "emits `package` observations with an exact `/etc/os-release` release that
outranks band inference." That half is corrected here, on principle, and the precedence rule it
implied is built now but dormant.

## The instrument does not emit observations — rejected on principle, not trimmed for time

ADR-076's consequence list said the instrument emits `package` observations into CVAP. That is
withdrawn. **An instrument whose entire purpose is to measure whether the pipeline is right must
not mutate what it measures.**

The concrete way it would have emitted — a non-scan-point writing observations through a
synthetic task and submission — is worse than merely unnecessary:

- It makes credentialed data **enter the pipeline by a path no scan point can use**. The
  measurement would then be validating the pipeline against ground truth that arrived through a
  mechanism production does not have — so a green measurement would attest to a data path that
  does not exist in the field.
- It **punches a hole in the ingest contract** (ADR-026's submission ledger, the `pending →
  accepted` ratchet, the lease/epoch checks) for a component that is not a scan point. That is
  exactly the shape of convenience path that becomes permanent: added "just for the instrument",
  relied on later, never removed.

This is recorded so a future reader sees the exclusion was **on principle — the instrument's own
purpose — not a deferral for time.** The observation-emission half of the credentialed capability
belongs to the production credentialed-host engine, which is deferred to full Phase 4 (ADR-076),
and which emits through the same scan-point ingest path every other engine uses.

Rejecting the mutation path leaves the exact-vs-inferred difference visible where it should be:
in the measurement itself. The instrument's release-attribution number (band vote vs
`/etc/os-release`) already shows when inference and ground truth disagree, without writing
anything.

## The release-precedence rule is built now, dormant

The rule ADR-076 anticipated — **an exact release read from `/etc/os-release` outranks the
band-vote inference** (ADR-064) — is a decision worth making while the measurement that motivates
it is in front of us, rather than rediscovering the reasoning at full Phase 4. So it is built now
and left dormant, the same way ADR-068 defined the `vulnerable` advisory state dormant before any
advisory finding could reach it.

- `internal/correlate.credentialedRelease` reads an exact release from a credentialed `package`
  observation, and `deriveRelease` uses it — with confidence 1.0 and a provenance recording that
  it outranked band voting — in preference to the vote.
- It is **unreachable today**: no scan point emits `package` observations, so on every real host
  `credentialedRelease` finds nothing and the band vote decides exactly as before. It is
  exercised only by its unit test (`release_precedence_test.go`), in isolation.
- It fires the day the deferred production engine emits `package` observations, with the reasoning
  already recorded and the shape (`packagePayload`, `release_source = "os-release"`) already
  defined.

The relation the rule encodes — ground truth beats an estimate of it — is the same relation the
instrument measures. Deciding it here keeps the two consistent.

## Consequences

- The Session 39 instrument (`cmd/cvap-credscan`) reads and measures; it writes nothing to CVAP
  and nothing to the target. Its only database access is read-only.
- ADR-076's "emits `package` observations" consequence is superseded by this ADR: that capability
  is the production engine's, excluded from the instrument on principle.
- The dormant precedence rule carries its own review trigger: the first host that resolves a
  release through `credentialedRelease` rather than the band vote — which cannot happen until the
  production engine ships — is when the rule stops being dormant and its 1.0 confidence and
  provenance are exercised against real data.
