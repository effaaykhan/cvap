# ADR-083: Banner capture is non-deterministic, and it silently moves release resolution between vote tiers

**Status:** Accepted
**Date:** 2026-09-10

Recorded from a discrepancy chased during Session 39, not merely noted: the same Exim service moved
release resolution from two votes to one between two hosts, with no change to the corpus, the rule, or
the scanner.

## The observation

- On `.138`, the fingerprint scan captured Exim's SMTP greeting and identified it, so it cast a
  release vote — two votes total (with OpenSSH), release resolved at the two-vote tier (0.80).
- On `.146`, the fingerprint scan produced only `service | method: none` on port 25 and **no banner
  observation at all** — Exim cast no vote, so release resolved on OpenSSH alone at the single-vote
  tier (0.60, ADR-080).

Same service, same release (resolute), same safe mode, same corpus.

## The chase — host and corpus ruled out by direct measurement

Connecting to port 25 on both hosts directly, both Exims greet promptly with a near-identical banner:

- `.146` → `220 test ESMTP Exim 4.99.1 Ubuntu …`
- `.138` → `220 honeypot ESMTP Exim 4.99.1 Ubuntu …`

So it is **not** a different version presenting a different banner (the banners match), **not** a
banner the corpus fails to recognise (`.138`'s identical banner matched fine), and **not** a
greeting delay or a silent service (`.146` greets immediately). The banner `.146`'s Exim reliably
sends was simply **not captured by the scan point** on that run — a banner observation that exists for
`.138` is absent for `.146`. The cause is scan-point-side: a transient or timing-dependent SMTP
banner grab, not the target and not the content.

## Why it is not cosmetic

Banner capture is an input to identification, identification is a vote, and votes decide release
resolution — which, since ADR-080, decides both *whether* a release resolves and *at what confidence
tier* (0.60 single-vote vs 0.80+ multi-vote), and release resolution gates advisory matching entirely.
So a non-deterministic banner grab means **a re-scan of an unchanged host can flip between resolving
and not, and between confidence tiers, with nothing having changed.** The two-vote threshold's entire
premise is that independent corroborating votes are meaningful; if whether a service votes is a coin
flip on capture, the corroboration the threshold rests on is not reliably reproducible.

## Consequence

- This is a reliability defect in the scan point's banner capture, and it goes to the backlog for a
  fix: banner grabs on volunteered-banner services (SMTP, SSH, FTP) must be reliable and, where they
  fail, retried and reported — a silent capture miss is under-identification that looks like a clean
  read, the failure class this project treats as worst.
- The confirming experiment is a re-scan of `.146`: if Exim then votes, the miss was transient
  (capture reliability); the direct greet already proves the host and corpus are not the cause, so the
  fix is scan-point-side regardless.
- It compounds ADR-079: safe mode already can't identify probe-only services (Apache), and now even a
  banner-volunteering service can be missed non-deterministically. Both narrow real identification
  below what the reachable surface would suggest, and both must be visible rather than silent.
