# ADR-072: An advisory finding's confidence is the minimum of its inference inputs

**Status:** Accepted
**Date:** 2026-09-09

Refines ADR-070. The advisory-finding path shipped with a constant confidence (0.5). A constant is
wrong for the same reason 1.00 would be: it does not say which of the finding's inputs is weak, and
this product's whole argument is that an **inferred** claim must not look as certain as an **exact**
one.

## Context — four inputs, three of them inferences

An advisory finding asserts "this installed package is at or below the version an advisory fixed."
That assertion rests on four things, and only one is exact:

1. **The comparator** (ADR-062) — dpkg/rpm says older-than-fixed or it does not. **Exact.** Not an
   inference; it contributes confidence 1.0.
2. **Release resolution** (ADR-064/065) — which distro release the host runs, from band voting.
   Tiered by corroboration: 2 agreeing votes → 0.80, 3 → 0.90, ≥4 → 0.95, scaled down by dissent.
   **Inference.**
3. **Version extraction** — the installed version, read from a **volunteered network banner**. Medium
   at best (ADR-014); an active probe is better, an unknown method worse. **Inference.**
4. **The product→package map** (ADR-064/071) — which source package a fingerprint product string
   means. Curated content, but a guess a human maintains, and its churn re-keys findings (ADR-071).
   **Inference.**

The comparator being exact is exactly why the finding's confidence is *not* the comparator's. Three
of the four inputs are inferences, and the finding is only as good as they are.

## Decision

**The finding's confidence is the minimum of its inference inputs** — `min(release_resolution,
version_extraction, package_map)`. The comparator contributes 1.0, so it never binds. Concretely,
today: `packageMapConfidence = 0.90` (a flat cap — even perfect release and version cannot make a
finding more certain than the package guess behind it); `versionConfidence` is 0.60 for a banner,
0.75 for a probe, 0.50 for an unknown method; release confidence is ADR-065's tier.

### Why minimum, not product

A product treats the inputs as independent multiplicative failures: four values around 0.8 collapse
to ≈0.41, which reads as "barely better than a coin flip" for a finding every input calls *quite*
reliable. That is misleadingly low, and it is also wrong in kind — the inputs are not independent
draws whose errors compound, they are a **chain**, and a chain is as strong as its weakest link. If
the release resolved on two shaky votes (0.80), the finding cannot be more trustworthy than that no
matter how clean the banner was; if the banner was the weak point (0.60), the release being
unanimous does not rescue it. Minimum encodes precisely that: **the finding is as trustworthy as its
weakest input, and no more.**

Minimum is also *interpretable*, which the record requires. A 0.80 advisory finding means every
input was at least 0.80 and the weakest was exactly 0.80 — a reader can invert the number to a
statement about the inputs. A product cannot be inverted: 0.41 could be one weak input or four
mediocre ones, and the reader cannot tell which. The cost of minimum is that it ignores
corroboration — three strong inputs and one weak one score the same as one strong and one weak — but
for a security finding that is the safe direction: do not let strength elsewhere paper over the one
input you should distrust.

### The weakest input must be visible, not just the number

So the next person reading a 0.60 advisory finding knows *which* input was weakest, the finding's
evidence carries the breakdown, not only the composed value:
`confidence_inputs: {release_resolution, version_extraction, package_map, comparator: "exact (1.0)",
composed, rule}`. A 0.60 finding shows `version_extraction: 0.60` beside a `release_resolution: 0.80`
and `package_map: 0.90`, so "the banner is why" is on the finding, not reconstructed later. This is
the same discipline as the release provenance (ADR-064) and the advisory evidence (ADR-070): the
verdict shows its work.

## Consequences

- `evaluateAdvisories` composes the confidence per finding from the release confidence (threaded out
  of `deriveRelease`), the version-extraction confidence (by observation method), and the flat
  package-map constant; `internal/version`'s exact comparator is deliberately absent from the min.
- The Metasploitable acceptance now asserts a **composed 0.60** (banner-bound), not a constant — an
  inferred finding that visibly does not claim the certainty of the exact comparator underneath it.
- The constants (0.90 map, 0.60 banner / 0.75 probe / 0.50 unknown) are first values, not measured
  ones — a review trigger: the first time a method or the map earns a different number from evidence,
  it moves here. They are named in one place (`internal/correlate/advisories.go`) so that is a small
  change, not a hunt.
- When credentialed assessment lands (the accumulating B30/B31 case), version extraction stops being
  an inference — the package manager's installed version is authoritative — and that input's
  confidence rises to near-exact, lifting the whole finding. The composition already expresses that:
  the min simply stops binding on version.
