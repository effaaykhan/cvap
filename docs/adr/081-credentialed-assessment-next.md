# ADR-081: Credentialed assessment moves next, ahead of B28 and the console

**Status:** Accepted
**Date:** 2026-09-10
**Supersedes:** `docs/phase-4-sequencing-decision.md` (the Phase 4 sequencing memo) and its deferral of
credentialed assessment to full Phase 4.

## The decision history, recorded straight

1. The Phase 4 sequencing memo recommended the enterprise console and B28 (service identification)
   first, credentialed assessment later.
2. The operator overruled that once already, narrowly (ADR-075): a **credentialed validation slice**
   next — an instrument, not the feature — because the unauthenticated accuracy ceiling could not be
   measured without credentialed ground truth.
3. On the memo's "disclosed ceiling" argument — that unauthenticated limitations are *disclosed*
   rather than *harmful* — the operator then let credentialed assessment itself stay deferred to full
   Phase 4.
4. **This ADR reverses step 3.** The disclosed-ceiling argument did not survive measurement.
   Credentialed assessment moves next, ahead of B28 and ahead of the console.

## Why the disclosed-ceiling argument died

A disclosed ceiling means "we see only some things, and we say so." The Session 39 measurement showed
the ceiling is not that. Of the findings the scanner **does** report, on the one service it could
see, **two in three are wrong** (65% false positives, ADR-078) — and wrong about *whether a patched
host is patched*, which is the question the product exists to answer. That is not a disclosed limit of
coverage; it is being confidently incorrect about the core claim.

Three facts decide it, and each was measured, not argued:

- **The mechanism is not fixable unauthenticated.** The Debian revision that distinguishes a patched
  build from an unpatched one is not on the wire (ADR-078). No banner parsing recovers it.
- **It worsens on well-maintained hosts.** `.138` was unpatched and still 65% wrong on OpenSSH,
  because a false positive needs the installed version to sit *between* advisory revisions. A patched
  production host sits between revisions on *most* packages — precisely where the error fires — so the
  rate is higher there, not lower.
- **B28 makes it worse, not better.** B28 identifies more services, so it produces more findings at
  35% precision. Reach multiplied by a wrong number is more wrongness. Sequencing B28 first scales the
  defect before fixing it.

And ADR-079 compounds it independently: safe mode is the correct default, and under it a third of
`.138`'s exposed surface was invisible. So the default posture **sees less than it appears to AND is
wrong about most of what it does see.** ADR-080's threshold change, correct on its own terms, makes
the unauthenticated advisory path reach *further* into that — more reason to fix correctness first.

## What did NOT change

The memo's **reach reasoning still stands.** Unauthenticated scanning remains the wedge: it is how the
platform discovers hosts, enumerates exposure, and builds inventory without credentials, and nothing
here demotes that. What changed is narrower and sharper: **unauthenticated advisory *matching* cannot
carry a product claim** — "this host is vulnerable to CVE-X" — because the evidence for that claim
(the exact installed version) is not observable unauthenticated.

So credentialed assessment is **not "depth" deferred until the breadth is polished. It is
correctness**, and it belongs before the features that scale the incorrect path.

## Consequence — the next session

The credentialed validation *instrument* exists and is proven (Session 39). The next session builds
the **production credentialed-host path**, which ADR-076 deferred:

1. Resolve the SSH cred+net placement ADR-076 named and left open — ADR-027 holds the credential in
   the runtime, ADR-047 grants net-to-target to an engine and not the runtime, and SSH needs both
   together with no derived token. This is the real architectural decision the instrument sidestepped
   by co-locating them in one operator process.
2. The credentialed-host engine emits `package` observations — activating the dormant path of ADR-077
   (exact `/etc/os-release` outranks the band vote; exact installed version drives matching).
3. Advisory matching on the exact installed version — no revision blindness — so the §6.2 ≤2%
   false-positive gate becomes achievable where unauthenticated matching measured 65%.
4. Re-run the §6.2 accuracy gates credentialed and record the precision delta against the
   unauthenticated baseline this session established.

The lab required for it is specified to the operator alongside this ADR.
