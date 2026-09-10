# ADR-078: Unauthenticated advisory matching cannot observe the Debian revision — a structural precision limit

**Status:** Accepted
**Date:** 2026-09-10

Recorded from the first real credentialed-vs-unauthenticated measurement (Session 39, ADR-075/076),
against a real host. This is a limit of unauthenticated matching, not a bug to be fixed by better
parsing.

## The measurement

A resolute (Ubuntu 26.04) host, three services held below their fixes, scanned unauthenticated and
then read credentialed. On the network-exposed packages the unauthenticated finding set was:

- **13 of 20 findings were false positives — a 65% false-positive rate.** Precision 35%.
- All 13 were OpenSSH; zero were Exim.

The three OpenSSH advisories for resolute, against the installed `1:10.2p1-2ubuntu3.5`:

| USN fixed version | CVEs | installed 3.5 is… |
|---|---|---|
| `1:10.2p1-2ubuntu3.2` | CVE-2026-35385, -35386, -35387, -35388, -35414 (5) | **above** — already patched |
| `1:10.2p1-2ubuntu3.4` | CVE-2026-59995 … -60002 (8) | **above** — already patched |
| `1:10.2p1-2ubuntu3.6` | CVE-2026-73281, -73282, -73283 (3) | below — genuinely vulnerable |

Credentialed truth is the 3 CVEs of `3.6`. The 13 false positives are exactly the `3.2` (5) and
`3.4` (8) sets — advisories the installed `3.5` already carries the fix for.

## The mechanism

The SSH banner reports `10.2p1` — the upstream version, with **no epoch and no Debian revision**.
Every advisory fixed version carries them: `1:10.2p1-2ubuntu3.N`. A comparison of a bare upstream
version against a revisioned fix treats the bare version as older than *every* revision, so the
matcher flags **every advisory for the package**, including the ones the installed revision already
fixed. The revision that would distinguish `3.5` from `3.2` is not on the wire; it was never
observable unauthenticated.

This is ADR-014's backport problem arriving from the unauthenticated side. ADR-014 established that
distro packages must match vendor advisories with backport-aware revision comparison; that
comparison is exact when the installed version is known (credentialed) and **impossible** when only
the banner's upstream version is known.

## Why Exim was clean, and why that is not reassurance

Exim's 0% false-positive rate is not accuracy — it is the absence of a boundary to get wrong. The
installed GA `4.99.1-1ubuntu1` is below *all four* Exim fixes, so every Exim advisory is genuinely
applicable and every flag is a true positive. The false positives appear only where the installed
version sits **between** two advisory revisions, which is exactly the OpenSSH case (`3.5`, between
`3.4` and `3.6`).

The consequence is the opposite of comforting: **a patched production host is where most packages
sit between revisions.** This host was deliberately left unpatched and still produced 65% false
positives on the one package with a revision boundary. A well-maintained host — most packages
patched to a revision short of the newest advisory — is *mostly* boundaries, so its unauthenticated
false-positive rate would be **worse, not better**.

## Consequence

- The execution-plan §6.2 false-positive gate (≤2%) is **not achievable by unauthenticated advisory
  matching** for any package whose installed version sits between advisory revisions. The precision
  ceiling here is structural, not a tuning target — 65% against a 2% gate is thirty times over, and
  no banner parsing closes it because the data is not transmitted.
- It is not fixed by better fingerprinting. The banner is complete; the revision simply is not part
  of what a service advertises.
- The correct resolution is credentialed assessment (ADR-075's direction), where the installed
  version is read and the comparison is exact — the same read that produced the truth this
  measurement was scored against.
- What unauthenticated matching *can* state honestly is a bounded claim: "an advisory exists for
  this package at or below the observed upstream version" — a candidate, not a confirmed finding.
  Whether the finding pipeline should mark such findings as candidates (lower confidence, or a
  distinct state) rather than assert them is a decision this measurement informs but does not make.
- No tuning was done against this sample (§5.5): the mechanism is recorded, not corrected.
