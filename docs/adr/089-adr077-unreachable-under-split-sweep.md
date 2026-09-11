# ADR-089: ADR-077 is correct as a unit but unreachable under the real sweep — a package-only host derives no family, so deriveRelease is skipped

**Status:** Accepted
**Date:** 2026-09-11
**Companion to:** ADR-077 (frozen; this records what first contact with real data showed, as ADR-077's
own review trigger required) and ADR-088 (which named the acceptance this session met).

Session 41 put a real credentialed `package` observation through correlation for the first time — the
event ADR-077 and ADR-088 both named as the moment the dormant release-precedence rule stops being
dormant. The operator asked, in as many words, to *check whether ADR-077 does what it says when an
exact release meets a band-resolved one, rather than assuming the dormant definition was right.* It
does not, and this records why — measured, not assumed.

## What ADR-077 claims

> `internal/correlate.credentialedRelease` reads an exact release from a credentialed `package`
> observation, and `deriveRelease` uses it — with confidence 1.0 and a provenance recording that it
> outranked band voting — in preference to the vote.

The rule is correct **as a unit**: fed the exact `.146` payload, `credentialedRelease` returns
`("resolute", true)`, and `deriveRelease` writes release=resolute at confidence 1.0 with
`{"source":"package_manager",...}` provenance. Its unit test passes.

## What first contact with real data showed

After the credhost engine's `package` observation for `.146` was correlated live, the asset's release
was still **`resolute` at confidence 0.8 with band-vote provenance** (`OpenSSH`/`Exim` port bands) —
not the 1.0 `package_manager` provenance ADR-077 promises. **ADR-077 did not fire.** The rule is
correct; the pipeline never reached it.

The sixteen inferred OpenSSH findings still closed as `refuted_by_credentialed` — but by
`evaluateCredentialed`, which is *ungated* by family, not by the release rule. So the acceptance held
while the flagged rule silently did not run. That is the dangerous shape: a green result that does not
attest to the rule it appears to.

## Root cause — the family gate meets the split sweep

Two facts combine, and neither is wrong on its own:

- **`credentialedRelease` lives inside `deriveRelease`, which is called only under `family != ""`**
  (`correlate.go`). Family is derived each sweep by `deriveServices`→`deriveAttribution` from the
  **service** observations in the current host group. A `package`-only host group produces no family.
- **The sweep builds each host from `groupByAddress(ListUnresolved(...))`** — only *unresolved*
  observations. A credentialed `package` observation arrives on its own, a day after the network scan;
  by then the service/banner observations are resolved (`asset_id` set) and are **not re-read** into
  the host group. So the sweep that carries the `package` observation carries no services, derives no
  family, and skips `deriveRelease` — and with it ADR-077 — entirely.

Measured on `.146`: service/banner observations correlated 2026-09-10 17:00; the `package` observation
correlated 2026-09-11 09:46, alone. Family from the package sweep: none. Release: untouched since the
band vote.

The rule is not reached because it is placed *downstream of a gate the credentialed data shape cannot
open*. ADR-088 said the rule fires "when a credentialed `package` observation reaches `deriveRelease`."
Correct — and under the real sweep composition, a package-only observation never does.

## Decision

Record the finding now; do not patch it inside this session's scope. This ADR is the report the
operator asked for ("report rather than work around"). The fix is a real design choice with more than
one defensible answer, and belongs to a scoped increment, not a hurried edit:

- **Re-read the resolved host into the sweep's group** so a late `package` observation is correlated
  with the services that give it a family. Most faithful to "the unit is a host"
  (`internal/correlate/CLAUDE.md`), but changes what a sweep reads for every observation, not just
  credentialed ones — needs its own safety and idempotence argument.
- **Run release resolution when a credentialed inventory is present even if family is unresolved.**
  `evaluateCredentialed` already reads the package observation ungated; release could resolve from
  `/etc/os-release` on the same basis (the os-release `ID` *is* the family). Narrower blast radius,
  but splits release resolution across two code paths.
- **Resolve family from the credentialed observation too**, so `family != ""` holds for a package-only
  host. Smallest change; makes the credentialed path self-sufficient for attribution.

The third is the likely answer — the credentialed observation carries `ID`/`VERSION_ID`, which *is*
ground-truth family and release — but it is a decision for the increment that implements it, with its
own review.

## Consequences

- ADR-077's release-precedence rule remains **effectively dormant on the fleet path** despite a real
  `package` observation having been correlated: it is reachable only when the host group also carries
  service observations, which the split sweep does not guarantee. Its unit test still passes and
  asserts nothing about this.
- The Session 41 acceptance (`.146`'s sixteen close as `refuted_by_credentialed` through the real
  pipeline, ADR-088) **is met** — and independently of ADR-077, because `evaluateCredentialed` is
  ungated. The supersession lifecycle works; the release-precedence rule is a separate, still-unproven
  thing.
- Review trigger: the increment that picks one of the three remedies above. Until then, a credentialed
  host's release confidence may read 0.8 band-vote even though an exact `/etc/os-release` was read —
  the number understates what is known. This is the latent-limitation shape: harmless today, a
  correctness gap the moment anything trusts release confidence as "how sure are we of the release".
