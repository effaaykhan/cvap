# ADR-059: Phase 3 sequences comparators → advisories → KEV/EPSS → NVD, behind a real-network validation

**Status:** Accepted
**Date:** 2026-09-07

## Context

Phase 3 is the knowledge pipeline and CVE matching — the first thing on the
path-to-sellable (execution-plan §7) that §2 puts explicitly out of MVP scope. Its
job is to turn the assets and software components the resolver already produces
into CVE-backed findings, and to prioritise them.

The execution plan assumed the knowledge pipeline ran **parallel** with discovery,
under a different person. It does not here — it runs **sequentially**, under the
same operator, after Phase 2. That changes what the phase must contain in one
concrete way: there is no second person absorbing the shared-dependency risk in
parallel, so the phase has to front-load its shared dependency and ship each stage
behind a gate before the next stage can lean on it. A stage that is wrong and
undetected does not get caught by a parallel track; it gets built on.

Three things about the domain make the ordering non-arbitrary, and each maps to a
failure pattern this project has already paid to learn (`phase-session-map.md` §5):

- **Version comparison is the silent-false-negative surface.** dpkg and rpm
  version semantics (epochs, tildes, `~rc1 < release`, distro-specific ordering)
  are subtle, and every downstream match calls them. A comparator that is subtly
  wrong does not crash — it judges a *vulnerable* package *not vulnerable*, and the
  finding never appears. That is the worst failure mode a scanner has, because it
  is invisible.
- **Vendor advisories are the matching authority, not NVD** (invariant #5,
  ADR-014). A distro backports a fix without changing the upstream version number;
  NVD's version ranges do not know that, the distro's advisory does. NVD is the
  *flagged fallback* for packages no advisory covers, low-confidence by construction.
- **KEV and EPSS are cheap and high-leverage.** ~2 days each, each keys only on a
  CVE id, and together they improve prioritisation more than anything else on the
  list.

And one thing the sequential order forces to the surface that the parallel plan
hid:

- **Advisory matching cannot begin until a host is attributed to the right OS and
  distro release.** An advisory feed is per-distro-release; match a host to the
  wrong feed and *every* finding on it is wrong — not low-confidence, wrong. Phase
  2 produces OS attribution at explicit low confidence, banner-inferred, validated
  only in the lab. Whether that attribution is good enough is not a gap to assess
  after building the matcher; it is the entry condition that determines whether the
  matcher can work at all. And lab-only attribution quality is precisely the kind
  of fact that holds until it meets a real network — so it is measured on real
  hosts *before* anything is built on it.

## Decision

**Phase 3 is built in the order below, behind a real-network validation, each stage
gated before the next depends on it.**

### Session 24 — Real-network validation (before P3.1)

Before any Phase-3 code, validate on real machines the operator owns what the lab
cannot: what real Windows and Linux hosts actually say about themselves (banners,
service fingerprints, OS signals), and **whether OS/distro-release attribution
survives outside the lab**. This measures exactly what P3.3 depends on. Building
advisory matching on lab-only attribution quality is the wrong order: if real
Windows and Linux hosts do not attribute cleanly, that is discovered here, against
a validation target, not later as a wave of wrong findings against a customer.

Output: a measured attribution accuracy figure on real hosts, and a decision on
whether P3.3's entry condition is met or needs discovery/fingerprint work first.

### P3.1 — Version comparators (dpkg + rpm), gated by a comparison corpus

Pure functions, no I/O, the foundation everything else calls. Gate them with a
**labelled comparison corpus** — `(a, op, b) → expected` triples drawn from the
distros' own test data and real advisory data, asserting the orderings that must
hold (epochs, `1.0~rc1 < 1.0`, backport suffixes). This is the content-agnostic-
test lesson (§5.3): a comparator test that only asserts "it runs" or "it is
transitive" passes against a comparator wrong on epochs. The corpus must *name the
orderings*, so losing a case is distinguishable from passing it.

### P3.2 — Vendor advisory ingestion

Ingest per-distro advisories (Debian DSA, Ubuntu USN, RHEL/Alma/Rocky OVAL, Alpine
secdb, SUSE) into the knowledge tables, normalised and buildable into a signed pack
(ADR-019, ADR-030, ADR-025 build-vs-consume). Feed acquisition and normalisation
only — matching is P3.3.

### P3.3 — Advisory matching. **Entry condition: OS/distro-release attribution**

Match the resolver's package inventory against the ingested advisories using the
P3.1 comparators, producing the first high-confidence CVE-backed findings.

**This stage does not begin until a host is attributed to its OS and distro
release with the accuracy Session 24 measured.** The attribution is the front of
this stage, not an exit finding of a later one — because a host on the wrong feed
produces uniformly wrong findings, and no amount of comparator or advisory
correctness recovers from that. An advisory-matched package version is the
strongest evidence the pipeline produces; that strength is entirely contingent on
the host being on the right feed.

### P3.4 — KEV and EPSS enrichment

Enrich the CVE-backed findings with CISA KEV (known-exploited) and EPSS
(exploitation probability). Sequenced here — early, right after there are CVEs to
enrich and before the NVD fallback — because each is cheap, keys only on CVE id,
and lifts prioritisation most. This stage consumes the `internet_reachable`
exposure signal (backlog #6): KEV × internet-reachable × EPSS is the prioritisation
the console leads with.

### P3.5 — NVD as the flagged fallback

Only now, and only for packages no vendor advisory covers. NVD CPE-range matching
is the low-confidence path; its findings are flagged low-confidence in the UI, as
the softmatch/weak-data presentation already does for OS inference (invariant #5,
ADR-014, the S23 SOC honest-weak-data rule). Built last and explicitly as the
fallback, so it cannot silently become the primary matcher — the latent-limitation
pattern (§5.4): "NVD is only the fallback" is true and harmless until someone wires
it ahead of advisories for a distro whose feed was flaky that day.

### P3.6 — Signed rule-pack packaging & offline import

Package the pipeline's output as a signed pack and import it read-only, the way
production consumes it (ADR-019). Last, so every earlier stage is exercised through
the *import* path before the phase closes — the build-vs-consume boundary proven
end to end, not asserted.

### Dashboard session — after P3.4

The enterprise-console session (backlog: *dashboard session*) belongs **after
P3.4**, agreeing with the stated instinct and for the stated reason: designing the
triage view before the data carries real confidence and priority distinctions means
designing it twice. By the end of P3.4 the full confidence spectrum is populated —
advisory-matched (high), Phase-2 banner-inferred (medium) and softmatch (unknown)
weak data, plus KEV/EPSS priority — so the view can be designed against real
distinctions. One design constraint carries the agreement: **build the confidence
axis as an open spectrum, not a fixed set of tiers**, so the P3.5 NVD-CPE
low-confidence CVE tier lands in the existing "low-confidence" lane without a
redesign. That is what keeps "after P3.4" from becoming "design it twice when P3.5
lands."

### Ordering, stated as dependencies

```
Session 24 (real-network validation: does OS attribution survive a real network?)
    └─> P3.1 comparators + corpus
            └─> P3.2 advisory ingestion
                    └─> P3.3 advisory matching   [entry: OS/distro attribution]
                            ├─> P3.4 KEV/EPSS enrichment   (early, cheap, high-leverage)
                            │       └─> Dashboard session  (enterprise console)
                            └─> P3.5 NVD fallback   (last, explicitly flagged low-conf)
                                    └─> P3.6 signed pack + offline import
```

## Consequences

- The subtlest, highest-blast-radius surface (comparators) is built first and gated
  by a corpus that names orderings — an otherwise-invisible failure mode is made
  visible before anything stands on it.
- OS attribution is validated on real hosts *before* P3.1, and gates P3.3 as an
  entry condition — so the wrong-feed failure is caught against a validation target,
  not discovered as wrong customer findings.
- The authority (advisories) precedes the fallback (NVD); the default matcher is the
  correct one and the low-confidence path is flagged and cannot silently take over.
- Prioritisation is good from the first CVE finding (KEV/EPSS at P3.4).
- The signed-pack boundary is exercised through the real import path before the
  phase closes.
- Three backlog items are pulled into "during Phase 3": `internet_reachable`
  (#6, consumed at P3.4), and the admin-console surfaces a rule-pack import UI
  shares with enrollment/audit (#5, #7). The enterprise dashboard is its own
  session after P3.4.

## Review trigger

Reopen before P3.2 begins if either holds: Session 24 shows OS/distro attribution
does not survive a real network at usable accuracy (P3.3's entry condition fails,
and discovery/fingerprint work precedes advisory matching); or the comparison
corpus cannot be assembled from the distros' own data and would have to be
hand-written (making it assert what we believe rather than what the distro defines).
