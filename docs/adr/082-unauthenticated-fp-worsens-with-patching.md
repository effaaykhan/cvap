# ADR-082: Unauthenticated advisory-matching precision worsens monotonically as a host is better maintained — the decisive case

**Status:** Accepted
**Date:** 2026-09-10
**Extends:** ADR-078 (this is ADR-078's decisive case, measured on a second real host)

ADR-078 recorded the mechanism — unauthenticated matching cannot observe the Debian revision, so a
package flagged against advisories it has already fixed — and measured a 65% false-positive rate on a
partly-patched OpenSSH. This ADR records the second measurement, which fixes the *direction* and
settles the Phase 4 argument.

## The two measurements, same package, same release, same scanner

| host | OpenSSH installed | vs newest fix | unauthenticated OpenSSH findings | false |
|---|---|---|---|---|
| `.138` | `1:10.2p1-2ubuntu3.5` | one revision behind (`3.6`) | 16 | **13 (65%)** |
| `.146` | `1:10.2p1-2ubuntu3.6` | **at the fix — not vulnerable** | 16 | **16 (100%)** |

`.146`'s OpenSSH is fully patched: it sits at the newest advisory revision and is genuinely
vulnerable to nothing. Unauthenticated matching reported 16 vulnerabilities, every one false —
including the very advisory (`3.6`) the host is patched *to*, because the banner's bare `10.2p1`
compares below a fix carrying epoch `1:` and a revision.

## The direction, stated explicitly

**Unauthenticated advisory matching gets worse as a host gets better maintained.** A fully-patched
package sits at or above every advisory revision; a bare upstream version compares below all of them;
so every advisory for the package fires. The more diligently a customer patches, the more wrong the
unauthenticated report becomes — 65% at one revision behind, 100% at the fix. The customer who does
the right thing receives the most incorrect assessment.

That is the opposite of how a security product must behave, and it is not a tuning problem or a
coverage problem: no amount of reach (more identified services), corpus work, or banner parsing
changes it, because the revision that would distinguish patched from unpatched is not on the wire
(ADR-078). Reach multiplies it — more identified packages at this precision is more wrongness
(ADR-081).

## Consequence

- This is the decisive evidence behind ADR-081: unauthenticated advisory matching cannot carry a
  product claim ("this host is vulnerable to CVE-X"), because on the hosts most likely to be in good
  shape it is confidently, monotonically wrong. Credentialed assessment — which reads the exact
  installed version and compares exactly — is the resolution, and it is correctness, not depth.
- The unauthenticated pipeline's honest output for a distro package is a *candidate* ("an advisory
  exists at or below the observed upstream version"), never a confirmed finding. Whether to represent
  it as a distinct lower-confidence state is a decision for the credentialed work (carried from
  ADR-080's review trigger).
- No inference was tuned against either host (§5.5): both are measurements, recorded.
