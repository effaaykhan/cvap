# ADR-061: Unauthenticated OS attribution — family, nullable release, confidence, and a reviewable service precedence

**Status:** Accepted
**Date:** 2026-09-08

## Context

ADR-060 measured P3.3's OS-attribution entry condition against a real host and
found it shut: the fingerprint engine produces a per-service `osHint`, but nothing
reads it, so the asset's OS is always null (§5.6, the write-only-field pattern).
B21 fixes the read. Fixing the read is the smaller half; the larger half is
**deciding what attribution means** — when several services suggest different
distributions, when only one carries a suffix, and when the banners name a family
but no release. This ADR records those decisions so a hardcoded order and an
overloaded null do not get argued about later from the code alone.

Two facts from ADR-014 constrain the model. Advisory matching keys the feed on the
**distro release** (`ubuntu2204`, `rhel9`), so a family without a release cannot be
matched. And an `osHint` is a string the host chose to send, so it is evidence, not
proof — a host matched to the wrong feed at high confidence poisons the knowledge
plane, not merely one scan.

## Decision

**Attribution is derived at correlation from the asset's service observations, and
it has three distinct outcomes — the middle one representable, not collapsed into a
null that means two things:**

1. **No attribution** — `distro_family` is null. "We know nothing about the OS."
2. **Family-only** — `distro_family` set (`ubuntu`), `distro_release` null. "We know
   it is Ubuntu and cannot pick a feed." **This is a distinct outcome from (1), and
   the distinction is load-bearing for Phase 3:** a family-only host is a candidate
   for credentialed follow-up (log in, read `/etc/os-release`, get the release); a
   no-attribution host is not, because there is nothing to act on. Collapsing the
   two into one null would lose exactly the signal that decides whether follow-up is
   worth it.
3. **Resolved** — `distro_family` and `distro_release` both set. Matchable against an
   advisory feed.

**From banners alone, the outcome is (2), not (3).** Metasploitable's banners say
`Debian-8ubuntu1`, `(Ubuntu)`, `3ubuntu5` — they name the family, never the release.
Reaching `ubuntu804` requires a package-version→release map (OpenSSH 4.7p1 ⇒ Hardy
8.04), which is knowledge-pipeline content, not banner extraction. **Attribution
does not guess a release it cannot read.** Release *resolution* is deferred to the
knowledge pipeline (P3.1/P3.2); until then, a banner-only host is honestly
family-only, which advisory matching treats as unmatched — the correct behaviour,
stated rather than papered over.

**Every attribution carries a confidence and a provenance chain.** Confidence is the
weakest-link of the contributing evidence (a banner-stated family is `ConfExactVersion`
territory; a shape inference is `ConfShape`), never raised above what any single
source justifies. Provenance records **which services contributed, which agreed, and
which were ignored** — because attribution is a claim and, exactly like a finding's
evidence, its basis must be reachable by an analyst on screen when it is wrong (and
it will be wrong). The provenance is stored with the asset and rendered on the asset
detail view, not left in the database.

**Service precedence is `ssh > http > smtp > ftp > smb`, and it is a DECISION with a
review trigger, not a constant.** When two services disagree on the family, the
higher-precedence service wins and the disagreement is recorded in the provenance
(the losing hint is listed as `ignored`, not discarded). SSH leads because its
banner names the vendor package most precisely; SMB trails because its OS hint is
coarse (`Windows` vs a distro). **This order is a reasonable default and it will be
wrong somewhere** — the first host with a stale SSH build and a current SMB stack,
or a container base that differs from the host, exposes it. Recording it here, with
that review trigger, is the difference between revising a decision and arguing about
a magic constant.

`osHint`'s non-authoritative flag (ADR-014, the mechanical `false` in
`payload.go`) is unchanged: attribution derived from hints is itself
non-authoritative, and `os_confidence` is how that survives into the model. Only
credentialed or protocol-authoritative detection may raise it, which is a later
diff a reviewer sees.

## Consequences

- The asset gains `distro_family`, `distro_release` (both nullable), `os_confidence`
  and `os_provenance` (jsonb). The three-state model lives in the nullability of the
  first two; the migration documents it so the family-only state is not read as a
  bug.
- B21 is satisfied when a family-only attribution with provenance lands on the asset
  and the asset detail view shows it; release resolution remains a knowledge-pipeline
  item, so P3.3 stays blocked on that half (ADR-060) — now with the family-only
  signal it needs to prioritise credentialed follow-up.
- The precedence is one named function with the order as data, so revising it is an
  edit to a table and a new ADR, not a hunt through branches.

## Review trigger

Revisit the precedence the first time a host is attributed to the wrong family
because a higher-precedence service was stale while a lower one was current — the
provenance chain is what will show it, because the ignored hint is recorded rather
than dropped. Revisit the whole model when release resolution lands: at that point
family-only should become resolved for hosts the knowledge map covers, and the
measure is whether Metasploitable reaches `ubuntu804`.
