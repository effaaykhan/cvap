# ADR-065: Release-resolution confidence tiers, and the service-coverage bound

**Status:** Accepted
**Date:** 2026-09-08

Refines ADR-064 (release resolution by upstream band). ADR-064 stands — band voting, the
two-vote threshold, the safety property, the feed-codename release. This refines two things in
it: how confidence is recorded, and an honest statement, measured, of how far release
resolution actually reaches on a real host.

## Context

Two things surfaced after ADR-064 was accepted:

1. **ADR-064's confidence was the share of clean votes that agree** (3/3 = 1.0, 3/4 = 0.75).
   That collapses a two-vote resolution and a four-vote one into the same number when both are
   unanimous — but four agreeing services is a stronger claim than two, and the finding pipeline
   should be able to weight them differently later.
2. **The two-vote threshold is right, but it exposes how few services vote.** On Metasploitable
   the resolver works — but on how many of its services, and why not more?

The second was measured rather than reasoned (`TestMetasploitableVersionCoverageMeasured`):
Metasploitable's eleven known safe-mode banners run through the built-in matcher yield a
**version** for exactly **four** services — `vsftpd 2.3.4`, `OpenSSH 4.7p1`, `MySQL
5.0.51a-3ubuntu5`, `ProFTPD 1.3.1`. Postfix is identified but carries no version in its banner;
telnet, VNC and IRC soft-match to a service with no version; HTTP/Apache, SMB/Samba and
PostgreSQL send no unsolicited banner at all in safe mode. Of the four version-yielders, two
band-vote a release (OpenSSH → hardy, MySQL → hardy); vsftpd's 2.3.4 (the backdoored build) and
ProFTPD (no advisory analogue) abstain. So the host resolves on **two votes** in safe mode, or
three if intrusive HTTP probing identifies Apache 2.2.8 — either way it clears the threshold.

This also reconciles the session-26 figure. S26 reported "6–7 of 11 identified"; that counted
services *identified* by any method, which includes the three versionless ones. It was not a
regression (the four version-matchers are all still present — the measurement asserts it) and
not wrong for service identification, but it **overstated coverage for the purpose of
version-dependent work** like release resolution and advisory matching, which need a version.
The honest number for that purpose is four.

## Decision

### Confidence is tiered by corroboration count, then scaled by dissent

The agreeing-vote count sets a base — **2 → 0.80, 3 → 0.90, ≥4 → 0.95** — and dissent scales it
by the share of clean votes that agree. So:

- unanimous `2/2` = 0.80, `3/3` = 0.90, `4/4` = 0.95 — more corroboration, higher confidence;
- a disputed plurality scales down: `3/4` = 0.675, `3/5` = 0.54;
- **a unanimous pair (0.80) outranks a disputed plurality (3/4, 3/5)** — a clean two-vote
  agreement is stronger evidence than a contested majority, which is the reasoning the two-vote
  threshold itself rests on.

The bases line up with the UI's existing confidence bands (≥0.9 high, ≥0.7 medium): a two-vote
resolution reads as "medium", three-or-more as "high". A resolved release is never collapsed
into one undifferentiated state; the number carries how corroborated it is.

### Coverage is bounded by service identification, and that bound is stated, not hidden

Release resolution can only vote with a service the corpus **identifies to a product and a
version**. On any real host it therefore reaches exactly as far as service identification does —
which today, in safe mode, is the four banner-versioned services above. This is a **B22 gap
(service identification), not a resolver limitation**: the resolver correctly resolves from what
it is given and correctly abstains on the rest. The distinction matters because the fix is in a
different place — more banner/probe matchers, not a better scorer — and because presenting the
resolver as "working" without the coverage number would overstate its reach on a real estate.

The specific services on Metasploitable that carry version-relevant data the corpus cannot turn
into a `services.version` today are named in **backlog B28**, measured, as the concrete
continuation of B22 — that list, not a better algorithm, is what most limits P3.3's practical
reach until the corpus covers more services.

## Consequences

- The finding pipeline can weight a two-vote release differently from a four-vote one; a
  resolved-but-thinly-corroborated release is visibly "medium", not "high".
- The session report, this ADR, and the design doc all state the coverage number honestly:
  release resolution works on the services the corpus can version-identify (four on
  Metasploitable in safe mode, two of them voting), and the rest are a service-identification
  gap, not a resolver failure.
- `TestMetasploitableVersionCoverageMeasured` is a regression lock on the four version-yielders,
  so a corpus change that drops one fails the build rather than silently narrowing P3.3's reach.

## Alternatives considered

- **Keep ADR-064's agreement-ratio confidence.** Rejected: it cannot distinguish two agreeing
  from four, which the finding pipeline needs.
- **Raise the threshold to three.** Rejected in ADR-064 and again here: the measurement shows a
  three-vote requirement would leave Metasploitable — and any host exposing only two
  version-identifiable services the keyspace covers — silently family-only, the outcome P3.3
  exists to prevent. Confidence tiers give the "three is stronger" signal without making two
  insufficient.
