# ADR-080: A single vote that uniquely narrows to one release resolves, at reduced confidence

**Status:** Accepted
**Date:** 2026-09-10
**Supersedes:** ADR-066 (the two-vote threshold's review trigger)

ADR-066 set the release-resolution floor at two agreeing votes and named its own review trigger:
the first real host that resolves on exactly one uniquely-narrowing vote. Session 39's measurement
fired it. This ADR changes the rule and records — plainly — that the measurement made it a smaller
win than it first appeared.

## The change

A **single clean vote whose candidate set is exactly one release** now resolves that release, at a
reduced confidence of **0.60** (below the two-vote tier's 0.80). Two-or-more agreeing votes keep the
existing tiers (0.80 / 0.90 / 0.95, ADR-064/065) unchanged. A single **ambiguous** vote — one
consistent with several releases — is not a clean vote and still abstains; that is the weak/backport
case the two-vote threshold was written for, and it is untouched.

`internal/domain.ResolveRelease` gains one branch (`singleUnique`); the ≥2 path is byte-identical, so
multi-vote hosts are provably unaffected.

## Why

The reasoning ADR-066 recorded for the two-vote floor was that a lone vote could be a backport or a
swapped build that coincidentally band-matches a release, and a wrong release poisons every advisory
finding. That holds for an **ambiguous** vote. It does not hold for a **unique** one: a vote whose
band excludes every release but one is a determination the system made, not a guess, and requiring
corroboration for it discards information already in hand.

And the cost asymmetry was backwards. A wrong release produces findings against the wrong feed —
visible, disputable, correctable. Abstention produces **silence, which reads as clean** — the exact
failure this phase was sequenced to prevent. Session 39's `.138`, single-service, proved it: the one
exposed service (OpenSSH) uniquely narrowed to resolute, and under the two-vote rule the scanner
resolved nothing and reported nothing on a host with real vulnerabilities.

## The win is smaller than first claimed — recorded plainly

The initial estimate was "0 findings → 3." The measurement contradicts it. On `.138`, resolving the
single OpenSSH vote activates advisory matching, and the banner-revision blindness of ADR-078 then
over-reports:

- **0 findings → 16 findings.** 3 true positives (the CVEs of the `2ubuntu3.6` USN, which the
  installed `2ubuntu3.5` is genuinely below) and **13 false positives** (the `3.2` and `3.4` USNs the
  installed version already carries — flagged because the banner's bare `10.2p1` compares below every
  revisioned fix). **Precision ~19%.**

So the change does not turn silence into signal; it turns silence into **mostly noise**. It is still
the right call, for the reason the asymmetry gives — a wrong finding is disputable and silence is not,
and an operator can act on 16 findings (dispute 13, remediate 3) but cannot act on nothing — but this
ADR must not read as a straightforward improvement, and it does not. The reduced 0.60 confidence
propagates into every finding on a single-vote resolution (min-of-inputs, ADR-072/073), so these
findings are marked as the less-corroborated claims they are.

The false-positive half is ADR-078's structural limit, not this rule's fault, and it is why ADR-081
moves credentialed assessment next: the single-vote resolution makes the unauthenticated advisory
path *reach further*, and reach times a wrong number is more wrongness.

## Verification

- `internal/domain` unit tests: a single unique vote resolves at 0.60; a single ambiguous vote
  abstains; two/three/four agreeing keep 0.80/0.90/0.95.
- End-to-end: the multi-vote `.138` (SSH + Exim, two agreeing votes) resolves resolute unchanged. The
  single-vote projection (OpenSSH alone) is 16 findings / 3 TP, measured from the openssh subset of
  the multi-vote run; a live SSH-only re-run confirms 0 → 16 when the host presents one service.

## Consequence

- No inference was tuned against the sample (§5.5): this is a resolution-logic change decided on the
  cost asymmetry, not a parameter fitted to `.138`. The 0.60 is chosen as "below two-vote," not to
  fit an observation.
- The review trigger for this rule in turn: whether single-vote findings should be a distinct
  finding state (candidate) rather than asserted at 0.60, given ADR-078 makes most of them false on a
  patched host. Deferred to the credentialed work.
