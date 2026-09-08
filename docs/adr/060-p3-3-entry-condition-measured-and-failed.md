# ADR-060: P3.3's OS-attribution entry condition, measured against a real host and failed (supersedes ADR-059 §P3.3)

**Status:** Accepted
**Date:** 2026-09-08

## Context

ADR-059 §P3.3 made OS/distro-release attribution the **entry condition** for
advisory matching, to be validated by Session 24's real-network scan. That
measurement has now run, against machines the operator owns, in safe mode. This
ADR records the result, because an entry condition that has been measured and
failed should say so in the decision record, not only in a session summary.

**The measurement.** Session 24 scanned Metasploitable 2 (`192.168.93.129`,
Ubuntu 8.04) unauthenticated. Its banners carry the OS explicitly: SSH
`SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1`, SMTP `220 metasploitable.localdomain
ESMTP Postfix (Ubuntu)`, MySQL `5.0.51a-3ubuntu5`, ProFTPD `220 ProFTPD 1.3.1
Server (Debian)`. The evidence a human needs to say "Ubuntu 8.04" is present three
times over.

**The result.**

- **Asset-level attribution: `os_family` and `os_version` are `null`.** The
  operator view — and P3.3 — see no OS at all on the most banner-rich host
  obtainable.
- **The only OS signal anywhere was a non-authoritative `Debian` hint** extracted
  from the SSH banner's `Debian-` prefix. It is the **wrong distro** (the host is
  Ubuntu) and carries **no release**. The `(Ubuntu)`, `3ubuntu5` and `8ubuntu1`
  signals in the SMTP, MySQL and SSH banners were not used.
- **Zero distro releases were produced**, against a host whose banners state the
  release. The modern Core host (`.139`, Ubuntu, `OpenSSH_…Ubuntu-2ubuntu3.6`)
  yielded hint `Ubuntu` (right family, still no release, also not promoted to the
  asset) — so attribution keys on the token immediately after the OpenSSH version,
  which is `Ubuntu-` on a modern build and `Debian-` on the 8.04 build: **same
  family, opposite answers.**

Two independent gaps produce this, and both are P3.3 entry conditions, not one:

- **B21 — attribution** does not reach a distro **release** and does not **promote**
  even the family hint to the asset (a non-authoritative hint is dropped at
  derivation).
- **B22 — version extraction** does not pull **product + version** from banners the
  corpus already receives. Apache 2.2.8, Samba 3.0.20, PostgreSQL, VNC and others
  came back `method: none` despite answering with identifying bytes.

The distinction matters: advisory matching needs **the right feed** (B21: distro +
release) *and* **the package and version to match against it** (B22). Either alone
is useless. The user framed B22 exactly: "if advisory matching cannot get apache2
2.2.8 from an Apache banner that states it, P3.3 has nothing to match."

## Decision

**P3.3's entry condition is measured and failed. P3.3 (advisory matching) is
BLOCKED — not merely informed — on B21 and B22.** This supersedes ADR-059 §P3.3's
treatment of the entry condition as a gate to be checked: it has been checked and
is **shut** until both land. The rest of ADR-059's sequence — P3.1 comparators,
P3.2 advisory ingestion, P3.4 KEV/EPSS, P3.5 NVD fallback, P3.6 signed pack — stands
unchanged.

**Acceptance is concrete, and its set is Metasploitable's services**, not a
synthetic fixture:

- B21 passes when attribution reaches **`Ubuntu 8.04`** from the same banners and
  writes it to the asset (`os_family`, `os_version`).
- B22 passes when version extraction reaches **`apache2 2.2.8`** (and the other ten
  services in the acceptance set) from banners the corpus already receives.

A build that cannot get the distro release and the package version from banners
that *state them* has nothing for advisory matching to consume. B21 and B22 are the
next session, **before Phase 3 begins**.

## Consequences

- Session 24's validation is now a recorded, failing measurement rather than an
  open question. Anyone reading the Phase-3 plan learns the entry condition is shut
  and why, from the ADR.
- The unidentified-service surface (backlog) is unblocked by **B22**, not by volume:
  fixing version extraction changes what "unidentified" means, so the surface is
  reassessed after B22, not before.
- **Corroborating safety evidence.** The measurement ran against ~15 deliberately
  exploitable services in safe mode and sent **zero payload probes and zero
  authentication attempts** — every observation was `method: banner` (read) or
  `none`. ADR-021's detection-not-exploitation line held under the most adversarial
  conditions available. That a scan of Metasploitable extracted only what the
  services *volunteered* is the strongest evidence to date that the safe-mode design
  works. Recorded prominently in `phase-session-map.md` §2 (S24).

## Review trigger

When B21 and B22 land, re-run the Session-24 acceptance set (Metasploitable's
services). P3.3 unblocks only when attribution reaches `Ubuntu 8.04` and version
extraction reaches `apache2 2.2.8` and its ten companions — measured against the
real host, not asserted.
