# Phase 4 sequencing decision — credentialed assessment vs. widening unauthenticated

**Date:** 2026-09-10 (S38 checkpoint)
**Status:** RECOMMENDATION SUPERSEDED by [ADR-075](adr/075-credentialed-slice-as-validation.md). The
operator overruled the "hold Phase 4, console/B28 first" recommendation below: the banner-inference
ceiling is a *validation* limit, not a product one (the §6.2 accuracy gates cannot be computed on a
real host without credentialed ground truth), so a **narrow credentialed slice** (Linux/SSH, package
inventory, one VM) comes next as a validation instrument — ahead of B28 and the console. **The reach
reasoning in this memo still stands** (unauthenticated remains the wedge; full Phase 4 stays held);
only the ordering changed. Read this for the reach argument and the cost analysis; read ADR-075 for
the decision.

Phase 3 closed with a coherent product: backport-aware CVE matching with exploitation-weighted
prioritisation, on real hosts, honest about its own ceiling. The question this memo answers is what
comes after the enterprise console (#12): keep widening the unauthenticated approach, or start Phase 4
credentialed assessment.

## Why the question is live now

Three independent gaps, each correctly deferred on its own, now resolve to the **same** answer —
credentialed assessment. Three arrivals at one answer is a different signal from one:

- **B30 — the keyspace holds *advised* packages, not *shipped* ones.** On a fully-covered release, a
  host running a package that never had an advisory matches nothing and reads clean for the wrong
  reason. A credentialed read of the package manager gives the *installed* set, so absence-from-the-
  keyspace stops meaning "safe".
- **B31 — advisory findings have no remediation lifecycle, and their identity re-keys on a content
  change (ADR-071).** Both problems are downstream of a banner-inferred package identity. A
  credentialed read gives the authoritative package name and version, so the identity is stable and
  the lifecycle is a simple version comparison.
- **The manual known-exploited case (B33).** KEV status is a fact about a CVE, but whether *this
  host* actually runs the vulnerable package rests on a banner-inferred, medium-confidence match
  (ADR-073). So a KEV finding on a real host can need manual confirmation of the package/version
  before it is actioned — the loudest signal in the product carries a manual step. A credentialed
  read attaches KEV status to a host without one.

The convergence is architectural: all three sit on the same weak input — an *inferred* package
identity — and credentialed assessment replaces the inference with a read.

## The actual choice

**Option A — keep widening unauthenticated.** B28 (service identification / version extraction), B24
(Debian-vs-Ubuntu family correctness), more advisory feeds. Each genuinely raises reach: more services
matched, more releases covered, fewer abstentions. **But none removes the ceiling** — every finding is
still a banner inference, still medium-confidence, still subject to B30/B31/B33. Widening moves the
product along the same asymptote; it does not change what the asymptote is.

**Option B — Phase 4 credentialed assessment.** Read the package manager over an authenticated
channel. This does not *widen* the unauthenticated approach; it **removes the inference** the three
gaps stand on. B30 dissolves (installed set is known), B31 dissolves (authoritative identity + version
comparison), B33 dissolves (KEV attaches to a host without manual confirmation), and a large part of
B28 stops mattering (you no longer need to squeeze a version out of a banner when you can read it).
Confidence rises from banner-medium to credentialed-high (ADR-073's ceiling lifts).

## What Phase 4 costs — stated plainly

- **Two new authenticated engines:** SSH (Linux package managers: dpkg/apt, rpm/dnf) and WinRM
  (Windows). Each is a scan-point-side capability with its own protocol handling.
- **A credential path — but ADR-020 already governs it:** credentials just-in-time, scoped,
  **memory-only on scan points, zeroised on completion or abort (ADR-020/057)**. The security model
  exists; the implementation (credential profiles, the JIT delivery, the zeroise discipline wired
  through the engines) does not.
- **Lab infrastructure:** a Windows domain and several distro VMs (at least a Debian/Ubuntu pair and
  an RPM host to exercise both comparators credentialed) — and an operator to stand them up. **This
  lab work is the operator's, not the model's**, and it is the real gating dependency: Phase 4 cannot
  be validated (corpus, golden results) without credentialed targets.
- **Scope:** this is not a single session. It is an engine track (two engines), a credential track,
  and a corpus/validation track — a phase, as the name says.

## What continuing unauthenticated buys — honestly, it is not nothing

- **The broader first sale.** Most scanning in the market is unauthenticated. A product that reaches
  every host on the network the moment it is pointed at a range has a wider wedge than one that needs
  a credential per host.
- **Credentials are the hardest thing to get from a customer.** They involve the customer's security
  team, change control, and trust the product has not yet earned. A product that *requires* them for
  every host asks for that trust up front, before the first finding proves value.
- **A narrower first sale for credentialed.** The credentialed product sells to customers who already
  trust you enough to hand over SSH/WinRM access — a later, warmer relationship, not a first touch.

So Option A is not merely "less correct"; it is the shape of product that lands the first customer.

## Recommendation

**Do not pull Phase 4 forward now. Sequence: enterprise console (#12) next → B28 service
identification → Phase 4, gated on a named trigger.** Reasoning:

1. **The convergence signal is real but points at a ceiling the product already discloses honestly.**
   The Phase-3 discipline — cannot-know, the confidence spectrum, `advisory_status` — means the gaps
   produce *bounded* answers, not *wrong* ones. That is a product you can sell with a straight face.
   The signal says "this is where the next depth is," not "the current product is broken."
2. **The market asymmetry decides the first product.** You sell the wedge that reaches every host.
   Phase 4's benefit is customer-specific (only helps hosts you have credentials for); its cost is
   high and partly the operator's (lab). Spending it before a buyer benefits is building ahead of
   demand.
3. **B28 is a better next dollar than Phase 4.** Better service identification raises reach *and*
   lifts the confidence ceiling (a version extracted by a probe's response-shape is a real sub-1.0
   input that finally exercises ADR-073's min-composition and pushes confidence up) — without the
   credential cost. It is the highest-leverage *unauthenticated* work, and it is a normal session,
   not a phase.
4. **Record the trigger so the eventual pull is deliberate, not rediscovered.** Start Phase 4 on the
   first of: (a) a design partner who will provide credentials for their hosts — which removes the
   market objection *and* supplies the credentialed targets the lab otherwise has to fabricate; or
   (b) the lab infrastructure being stood up (the operator's dependency); or (c) a fourth independent
   gap resolving to credentialed.

**The condition under which I would flip to "start Phase 4 now":** if your near-term buyers are
credential-providing enterprises — a design-partner or top-down enterprise motion rather than a
self-serve/wide first sale. Then the market objection is moot, the lab burden is shared by the
partner's real hosts, and credentialed depth becomes the differentiator that makes the enterprise
console credible. That is a go-to-market fact you hold and I do not, which is why it is the operator's
decision and not mine.
