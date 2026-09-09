# ADR-073: The advisory-confidence inputs are 1.0 pass-throughs today, and min() is untested

**Status:** Accepted
**Date:** 2026-09-09

Refines ADR-072. ADR-072 decided the composition — an advisory finding's confidence is the minimum
of its inference inputs — and that decision stands. It also assigned first-value constants to two of
those inputs (banner version extraction 0.60, product→package map 0.90). This ADR corrects those:
they are **1.0 pass-throughs today**, and the correction matters enough to record because it changes
what a reader should believe the number means.

## Context

ADR-072's 0.60 and 0.90 were invented. There is no measurement, no corpus, no reasoned tier behind
them the way ADR-065 stands behind release confidence — they were plausible-sounding numbers that
made `min()` *look* like it was weighing three inputs when it was really weighing one made-up value
against another. That is the shape this project keeps finding: a guess presented as a measurement,
and a guard written for an input that does not exist yet.

There was also a floor. `minConf` skipped any input `<= 0`, and `versionConfidence` returned 0.50
for an unknown method. Both are the same latent-defect shape — a guard that does nothing today
(every input is positive, every method is "banner") and becomes a **wrong answer** the moment the
input it was written for appears: a genuinely weak input (a 0.4, or a 0) would be raised or skipped
to make the finding look better than its evidence.

## Decision

**Version extraction and the product→package map contribute 1.0 today.** We have no principled
sub-1.0 value for either, so we assign none and say so, rather than inventing one. `min()` is
therefore currently the **release confidence alone** (ADR-065) — the one input with a real,
reasoned value.

**State this as coverage, not certainty.** The min mechanism is correct and **untested as a
composition**, because there is no weak input in the tree to exercise it. A reader seeing a 0.80
advisory finding should understand it as "the release resolved at 0.80, and nothing else is being
weighed yet" — not as "three inputs were evaluated and the weakest was 0.80." The finding's evidence
carries this: `version_extraction: 1.0`, `package_map: 1.0`, and the rule note says they are
pass-throughs, so the coverage is visible on the finding, not assumed by the reader.

**Drop the floor.** `minConf` no longer skips low inputs and no method defaults to 0.50. A finding
that inherits 0.4 carries 0.4 and is honestly weak. An input that is genuinely absent is passed as
1.0 (not binding), never as 0 to be guarded against — the composition is over real values only.

### Review trigger

The first input that carries a real sub-1.0 confidence is the case that tests `min()` as a
composition rather than a pass-through. **B28's service-identification work is the expected source:**
a version extracted by response-shape (a probe's differential) rather than a volunteered banner is
exactly the weaker claim that should pull a finding's confidence down. When that lands,
`versionExtractionConfidence` stops being a constant and becomes a function of the extraction method,
and the first finding whose version input is below the release confidence is the first real exercise
of the minimum. At that point the constants move to measured or reasoned values, in the one place
they live (`internal/correlate/advisories.go`).

## Consequences

- `evaluateAdvisories` composes `min(releaseConf, 1.0, 1.0)` = releaseConf today; the Metasploitable
  acceptance now asserts **0.80** (the release confidence for two unanimous votes), not 0.60, and
  asserts that version/map are 1.0 and the composed value equals the release confidence — so a
  regression that reintroduced an invented constant, or a floor, would fail.
- The backlog's sequencing note is corrected accordingly: version extraction is not a confidence
  *cap* today (it is a pass-through); it *becomes* one when B28 gives it a real value, and
  credentialed assessment removes that ceiling by reading the installed version authoritatively.
  The three-gaps-point-at-credentialed accumulation still holds — this refines when the third gap
  bites (at B28), not whether it exists.
- ADR-072's composition decision is unchanged. Only its input constants and the floor are corrected.
