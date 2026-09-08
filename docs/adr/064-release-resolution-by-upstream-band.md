# ADR-064: Release resolution by upstream version band

**Status:** Accepted
**Date:** 2026-09-08

## Context

OS attribution reaches a distro FAMILY from banners (B21, ADR-061) but never a RELEASE:
`Attribution.DistroRelease` is always nil, and a family-only host is unmatchable, because
advisory matching keys on the release (ADR-014). ADR-061 deferred the release to
"knowledge-pipeline content, not banner extraction." This ADR is that content.

Sessions 29–30 measured the options against the dev database rather than argued them:

- The **packaging suffix** (`-3ubuntu5`) does not survive into `services.version` for most
  services (SSH diverts it to a separate field; only MySQL's protocol packs it), and the bare
  suffix is not release-discriminating anyway. The suffix bridge is dead.
- A **release-baseline feed** (every release's shipped versions) is authoritative but a second
  knowledge pipeline.
- The **upstream version band** — the package's upstream version with epoch and packaging
  revision stripped — *does* discriminate: session-30 widened the hardy import to 537 USNs (190
  packages) and found hardy's band unique in the keyspace for every service package
  (`openssh 4.7p1`, `apache2 2.2.8`, `mysql 5.0.51a`, `samba 3.0.28a`, `vsftpd 2.0.6`), because
  Ubuntu bumps a package's upstream version every release.

## Decision

Resolve the release by **upstream-band voting over the advisory keyspace** — no baseline feed,
no per-release rename map. Mirrors B21's split: a pure decision in `domain.ResolveRelease`,
gathering and promotion in `correlate.deriveRelease`, running only under a known family.

**Why this is acceptable inference, and the property everything else serves: every failure
mode is UNRESOLVED, never wrong.** A band collision yields two candidates and no clean vote; an
absent release yields no match; a swapped-in build (Metasploitable's Samba 3.0.20) matches
nothing and abstains; a product with no advisory analogue abstains. Unresolved is already a
representable, honest state — ADR-061's nullable `DistroRelease`, meaning family-only and
unmatched-for-advisories. A *wrong* release would poison every advisory finding on the host;
this design cannot produce one, which is why unauthenticated inference is admissible here where
it would not be if the failure mode were a confident wrong answer. Credentialed assessment
(Phase 4) reads `/etc/os-release` and is strictly better when it lands; this is the right
unauthenticated floor until then.

### The band is defined once, in Go

`domain.UpstreamBand` strips the epoch and the Debian revision (`1:4.7p1-8ubuntu1.2` → `4.7p1`)
and is the ONE authority for what a band is — applied to both the observed version and the
keyspace fixed versions. SQL never extracts a band: that would be a second definition that
drifts (the two-writers-one-fact hazard), and version semantics belong to Go (ADR-062). Note
this is band *equality*, not version *ordering* — the store read narrows to a product's
packages, Go bands and compares; ADR-062's comparators still own all ordering, including the
`installed < fixed` verdict the resolved release then feeds.

### The threshold

A release is **RESOLVED** only when it has at least **two** clean, agreeing single-release
votes AND is the unique leader; otherwise the asset stays **family-only**. (`ReleaseVoteThreshold
= 2`.) Rationale, decided against the session-30 measurement:

- **One vote is not enough.** A lone service can be a backport or a swapped-in build that
  coincidentally band-matches a release, and a wrong release poisons every finding.
- **Two independent services agreeing corroborate.** The chance that two unrelated services
  both band-match the same *wrong* release is low — Metasploitable's two swapped builds matched
  *nothing* and abstained, which is the common shape.
- **Three is clearly enough** and is what the acceptance host provides.
- A tie or a split never resolves: the leader must be unique. Everything short of the bar is
  family-only, never a guessed release.

Confidence is the share of clean votes that agree (3/3 = 1.0, 3/4 = 0.75) — how corroborated
the answer is, not how good a band match was (that is exact, or the service abstained).

### The release is the feed's codename

The resolved value is the advisory feed's release key — `hardy`, not `ubuntu804`. That is what
P3.2 matching consumes directly (`advisory_fixed_packages.distro_release`), so there is one
release namespace and no codename↔version translation table — which would be another rename-map
to maintain and get wrong.

### The product→package map is content

`product_packages` (migration 0035) maps an observed service Product (`OpenSSH`) to the Ubuntu
source package(s) the keyspace uses (`openssh`). It is global knowledge content, imported
offline as `cvap_knowledge_import` (ADR-030/ADR-063), reviewable and changeable without a code
deploy — ADR-048's corpus argument. Band matching tolerates renames (`mysql-dfsg-5.0` →
`mysql-5.1`) because it keys on the band, so a product may list packages from several eras.

### Provenance carries a fourth role: abstained

Family provenance (ADR-061) has contributed/agreed/ignored. Release provenance adds
**abstained** (with a reason: no-analogue vs band-mismatch), because "absence is not evidence"
must be *visible*: an operator has to see which services could not vote and why, or a release
with three votes looks identical to one with three votes and four silent mismatches. It is
stored even when unresolved, so a family-only outcome shows why it did not resolve. This is the
dashboard's material on the asset page.

## Consequences

- Coverage is a function of how many releases are imported: a release absent from the keyspace
  yields abstention, never a wrong release. Broad per-release USN import (session-30's
  pagination) is the lever, and it lifts advisory-matching coverage regardless.
- Acceptance (`TestReleaseResolvesEndToEndOnMetasploitable`): the host resolves to `hardy` on
  three agreeing votes with three recorded abstentions, and the resolved release drives a real
  CVE-2012-2122 match against the measured MySQL version — the first end-to-end family → release
  → comparator → advisory finding on a real machine.
- **`product_packages` is the SIXTH table `cvap_knowledge_import` writes** — the visible,
  reviewable widening ADR-063 requires be recorded (it said the grant is "on exactly the five
  knowledge tables ... adding a sixth is a visible, reviewable widening"). This ADR is that
  record; `internal/store/CLAUDE.md`'s global-knowledge-table list is updated from it.
- **It is also the FIFTEENTH table the v2 ERD does not draw.** ADR-063 recorded the fourteenth
  (`knowledge_feed_status`) and noted ADR-029's per-table-annotation approach had passed its
  scaling threshold; the fifteenth is folded into that same review — backlog **B27** (redraw
  the ERD, supersede ADR-029), not a new per-table note.

## Review trigger — band collisions

The band is not a universal 1:1: two frozen adjacent releases can ship the same upstream
version (`apache2 2.2.22` in **both** precise and quantal, measured in session 30). Such a
service casts a multi-candidate vote that corroborates a leader it contains but never pins on
its own. Revisit this ADR when a collision blocks a resolution that matters — the fix is likely
a tie-breaking signal (the packaging revision, or another service), and the ambiguous vote in
the provenance is what will show it, the way ADR-061's ignored hint shows a wrong precedence.

## Alternatives considered

- **Release-baseline feed (ADR-060/session-29 option b).** Most authoritative — resolves
  stable-named packages that never had a USN — but a second pipeline. The band test showed it is
  not needed for the acceptance host or the common services, so it is an enhancement, not a
  prerequisite; weigh it only if advisory-only band coverage proves too thin.
- **Packaging-suffix matching (session-29).** Dead: the suffix does not survive extraction for
  most services and is not release-discriminating.
- **Pulling Phase-4 credentialed release forward.** The strictly-correct answer
  (`/etc/os-release`), but a larger scope change; the band gives an honest unauthenticated
  answer now without forcing that decision.
