# ADR-075: A narrow credentialed slice as a validation instrument — overruling the S38 hold

**Status:** Accepted
**Date:** 2026-09-10

The S38 sequencing memo (`docs/phase-4-sequencing-decision.md`) recommended holding Phase 4 behind a
named trigger and taking the enterprise console then B28 first. **The operator overruled that
recommendation, narrowly.** This ADR records the overrule and its reasoning, supersedes the memo's
recommendation, and scopes what is done instead. The memo's *reach* reasoning is preserved and still
governs (see below); what changes is the frame.

## Why the recommendation was overruled

The memo treated the banner-inference ceiling as a **product limitation** — a bounded, honestly
disclosed limit the product can sell on the near side of. It is more precisely a **validation
limitation**, and that changes the decision:

- **Two real hosts have ever been scanned.** The rpm comparator has **never** been proved in situ.
  There is **one** advisory vendor (USN).
- **The §6.2 FP/FN accuracy gates are computed against labelled lab targets.** On a real host there
  is no ground truth, so **neither number can be computed at all**. The product's headline accuracy
  claim exists only against the lab it was built with.
- **Credentialed assessment is the ground-truth generator.** Its first value is not more findings; it
  is the *only* way to learn whether the unauthenticated findings on a real machine are right. A read
  of the package manager is the labelled truth that a banner inference can be measured against.

Two consequences of this frame correct the memo:

- **B28 does not raise confidence, only reach.** It produces more banner-derived versions at the same
  medium confidence and the *same unmeasured accuracy* — a wider funnel whose conversion rate nobody
  has measured. The memo's "raises reach AND confidence" claim was its weakest, and it is withdrawn.
- **The console before that measurement is wrong on the memo's own terms.** The console is the surface
  where a design partner judges trustworthiness; building it over findings whose accuracy against a
  real machine is unknown builds a trust surface on an unmeasured base.

## What is preserved from the memo

The **reach reasoning stands**: unauthenticated remains the wedge. Most scanning in the market is
unauthenticated; credentials are the hardest thing to get from a customer; a product that needs them
for every host has a narrower first sale. Nothing here reverses that. This is precisely why the
overrule is *narrow*: credentialed arrives as a **validation instrument**, not as the depth product,
and not as full Phase 4.

## Decision

**Build a narrow credentialed slice next, ahead of B28 and the console.**

- **Scope:** Linux over SSH, **package inventory only**. No Windows, no WinRM, no domain, no lab
  build. One VM the operator stands up this week. Credentials are governed by ADR-020 already —
  just-in-time, scoped, **memory-only on scan points, zeroised on completion or abort** (ADR-020/057);
  the slice wires that discipline through an SSH package-inventory read and nothing wider.
- **It does three things at once, at a fraction of full Phase 4's cost:**
  1. **Ground truth for banner inference on a real host** — the measurement that does not exist and
     cannot be made any other way. Every unauthenticated finding's package/version can be checked
     against the credentialed installed set.
  2. **Proves the rpm comparator in situ** if the VM is Rocky or Alma — real rpm versions through the
     Go comparator against the librpm oracle, on a real host, not the corpus vectors. This **closes
     B26**, operator-blocked for six sessions.
  3. **Removes B30 for credentialed hosts** — the installed set is known, so absence-from-the-keyspace
     stops meaning "safe" on any host the slice reads.
- **Then B28, then the console — both informed by an actual accuracy number rather than a lab one.**
  The sequence the memo proposed is kept; what changes is that a real-host accuracy measurement now
  precedes it.

## Consequences

- **Full Phase 4 remains held** behind the S38 trigger (Windows/WinRM, a domain, the full lab). This
  slice is deliberately not that: it is the smallest credentialed capability that generates ground
  truth. The S38 memo's *decision* to defer full Phase 4 stands; only its "console/B28 first, no
  credentialed yet" ordering is superseded.
- **The §6.2 accuracy gates become computable on a real host** for the first time — but only where the
  advisory keyspace covers the distro (USN → Ubuntu). The distro choice for the first VM follows from
  that (see below); it is an operational decision the operator makes.
- **B26 unblocks** the moment the VM is an rpm host; the operator is standing it up.
- The reach reasoning is preserved verbatim in the memo, which is annotated as superseded-on-the-
  recommendation, not deleted.

## The first VM's distro — the measurement decides it

The slice's stated first purpose is the accuracy measurement the operator cited (§6.2 FP/FN on a real
host). That measurement compares credentialed-truth findings against the unauthenticated findings, so
it can only be computed where the advisory keyspace produces findings — and the keyspace is **USN
only**. On a Rocky/Alma host there are no advisory findings to validate, so the §6.2 numbers cannot be
computed there at all; that VM would prove the rpm comparator and measure version-extraction, but not
"whether the findings are right."

So the two goals pull apart, and the first VM should serve the one that is unique:

- **A current, densely-covered Ubuntu LTS (jammy 22.04 recommended; noble 24.04 equally fine)** is the
  only host on which the §6.2 finding-accuracy numbers can be computed — the measurement that cannot be
  made any other way — and it exercises the keyspace where it is *dense*, a real contrast to
  Metasploitable's degenerate hardy. This is the recommended first VM.
- **Rocky/Alma is the essential second VM** — it closes B26 and proves the rpm comparator in situ, a
  distinct correctness gap — but on its own it cannot produce the finding-accuracy number, because no
  RHEL/Rocky advisory vendor is ingested (one-vendor limit). Closing that fully is a second-vendor
  feed, beyond this slice.

Recommendation: **jammy first** (accuracy measurement), **Rocky/Alma second** (B26 + rpm in situ).
The operator decides and stands up the VM.
