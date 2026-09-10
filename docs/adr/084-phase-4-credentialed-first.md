# ADR-084: Phase 4 leads with credentialed assessment — the decision, and the arc that reached it

**Status:** Accepted
**Date:** 2026-09-10
**Supersedes:** `docs/phase-4-sequencing-decision.md` (the Phase 4 sequencing memo). Completes the
reversal ADR-081 began, now decided against the full measurement set (ADR-078/079/082/083).

## Decision

Credentialed assessment is the next Phase 4 work — **ahead of B28 (service identification), ahead of
the enterprise console, and ahead of any further unauthenticated widening.** No feature that scales or
broadens the unauthenticated advisory path is built before credentialed assessment lands.

## The arc — recorded because the process is the point

This decision reversed itself twice, and the record matters as much as the conclusion:

1. **The memo recommended** the enterprise console and B28 first, credentialed assessment later.
2. **The operator overruled it (ADR-075)** — narrowly — for a credentialed validation *slice*: an
   instrument to measure the unauthenticated accuracy ceiling, because that ceiling could not be
   quantified without credentialed ground truth.
3. **The operator then deferred** credentialed assessment itself back to full Phase 4, on the
   argument that the unauthenticated ceiling was *disclosed* (we see some things, and say so) rather
   than *harmful*.
4. **This ADR reverses step 3.** The disclosed-ceiling argument did not survive contact with a real
   host.

The decisive thing is *how* it was overturned: **not by whoever argued better, but by a host.** The
instrument built in step 2 to measure the ceiling produced numbers that refuted the premise of step
3. An argument that sounded right lost to a measurement. That is the record worth keeping.

## The evidence, in order of weight

1. **ADR-082 — the output is wrong, and wrong in the worst direction.** Unauthenticated advisory
   matching was 65% false on a partly-patched OpenSSH and 100% false on a fully-patched one, and the
   direction is toward *worse* as the host is better maintained. A product whose accuracy degrades as
   the customer does the right thing cannot carry a product claim. This is not a ceiling to disclose;
   it is a defect in the output.
2. **ADR-078 — it is not addressable on this side of the wire.** The Debian revision that separates
   patched from unpatched is not in the banner. No corpus work, no fingerprint improvement, no feed
   change recovers it.
3. **ADR-083 — the path is unreliable in a second, independent way.** An unchanged host resolved
   differently between scans because banner capture is not reliably reproducible, which undercuts the
   corroboration premise the two-vote threshold rests on and means every number in the sequence
   carries an unquantified reproducibility error.
4. **ADR-079 — the default posture compounds both.** Safe mode is the correct default, and under it a
   third of an exposed surface was invisible.

## What did not change

The memo's **reach argument stands and is preserved.** Unauthenticated scanning remains the wedge for
discovery and inventory — enumerating hosts and exposure without credentials — which is what it is
genuinely good at, and nothing here demotes it. What died is narrower and sharper: the claim that
unauthenticated *matching* is merely *bounded*. It is not bounded; it is **wrong, wrong in the worst
direction, and not fixable where it lives.** Advisory matching needs the exact installed version, and
that is only available with credentials.

## Consequence — order of work

1. **Fix ADR-083 first.** Banner capture non-determinism is a scan-point reliability defect that
   affects every future measurement, credentialed ones included. Phase 4 is not built on a scan point
   whose identification is a coin flip.
2. **Then scope the first credentialed session**, whose gating decision is the ADR-027 (credential in
   the runtime) versus ADR-047 (net-to-target in an engine) placement for SSH — settled before code.
   `.138` and `.146` are available as targets; AlmaLinux for B26 is built when needed.
