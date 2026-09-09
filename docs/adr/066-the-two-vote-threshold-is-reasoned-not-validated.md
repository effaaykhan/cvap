# ADR-066: The two-vote release threshold is reasoned, not validated

**Status:** Accepted
**Date:** 2026-09-09

Refines ADR-064 (`ReleaseVoteThreshold = 2`) and ADR-065 (confidence tiered by vote count).
Both stand. This records what the threshold has and has not been tested against, so the number
is not mistaken for a validated one.

## Context

The two-vote threshold was reasoned from the session-30/31 measurement: one clean vote can be a
backport or a swapped-in build, two independent services agreeing corroborate, and raising the
bar to three would leave ordinary hosts — those exposing only two version-identifiable services
the keyspace covers — silently family-only, the exact outcome P3.3 exists to prevent (ADR-065).

But every real resolution to date is a single data point that cleared the bar by a margin:
Metasploitable resolved on **three unanimous votes** (confidence 0.90). The boundary cases the
threshold actually governs have **never occurred on real data**:

- a host that resolves on **exactly two** agreeing votes (confidence 0.80), and
- **two-with-dissent** — two for one release, one for another — where the plurality rule and the
  dissent-scaled confidence do the work.

The number is therefore **reasoned, not validated**. Nothing has yet exercised the line it draws.

## Decision

Record this as a **review trigger, not a gap** — there is no fix to apply, because the threshold
is not known to be wrong; it is untested at its boundary.

**The trigger: the first real host that resolves on exactly two agreeing votes** (and,
separately, the first that resolves with a dissenting vote present). When it occurs:

- check the two-vote resolution against ground truth where it can be had — a credentialed read
  of `/etc/os-release` (Phase 4), the operator's own knowledge of the host, or a subsequent scan
  that adds a third service;
- if a two-vote resolution proves **wrong**, that is the signal to raise the threshold, or to
  require the two votes come from independent evidence *kinds* rather than two banners — not a
  decision to take speculatively now, against no failing case;
- if it proves **right**, the threshold has its first validation at the boundary, and this ADR
  records that rather than being superseded.

Until then the threshold stands as reasoned, and the confidence tier (0.80 for two votes, "medium"
in the UI, ADR-065) already carries the caveat to anyone reading a two-vote resolution: it is the
weakest resolution the system will make.

## Consequences

- Not a gap to close before P3.4: raising the threshold now would suppress exactly the ordinary
  two-service hosts P3.3 is meant to reach, on no evidence that two votes are unsafe.
- The trigger is cheap to honour because the resolver already records the vote count and
  provenance on every asset (ADR-064): a two-vote resolution is queryable, not something a
  future session has to reconstruct.
- Phase 4 credentialed assessment, when it lands, is the natural validator — it reads the release
  directly, so a host it covers turns every prior banner-inferred two-vote resolution into a
  checkable prediction.
