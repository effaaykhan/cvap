# Spec: surfacing credentialed vs inferred findings, and their lifecycle

Design note for the enterprise console (backlog #12) and the finding pipeline. Spec only — no UI
code this session. Written now because credentialed assessment (Session 40) makes a host carry
*exact* claims beside the *inferred* ones, and ADR-078/082/085 make the distinction load-bearing:
the inferred claim about a package is 65–100% likely to be wrong, the credentialed one is exact.

## The distinction must be visible

A finding already carries the fields that express this; the console must render them, not hide them:

- **Provenance / source.** Credentialed: read over SSH, `source = package_manager`, exact installed
  version. Inferred: banner-derived, `source = network`, a *candidate* not a confirmation (ADR-078).
  Surface a per-finding label — "credentialed (exact)" vs "inferred (candidate)" — on the finding
  list and detail, not only in the evidence blob.
- **Confidence reflects it.** A credentialed finding is ~1.0 (the version was read). An inferred one
  is the composed min of its inference inputs (ADR-072/073), which is lower and must read as lower.
- **The asset's release** shows the same way: read from `/etc/os-release` (exact) vs resolved by band
  vote (inferred), with its own confidence — the asset page already holds both provenances.

An operator triaging a backlog must be able to tell, per finding, whether it is a fact about the host
or a guess about it. That is the difference between a 0%-FP and a 65%-FP claim.

## The supersession lifecycle — the common migration case

During migration a host will have BOTH an inferred finding (from an earlier unauthenticated scan) and
a credentialed finding for the **same package and CVE**. An operator seeing two findings for one
package with different confidences needs to know which one is true. The rule:

- **The credentialed finding supersedes; the inferred one closes.** The credentialed read is ground
  truth for that (package, CVE) on that host; the inferred finding was a candidate the credentialed
  read has now resolved — confirmed or refuted.
- If credentialed **confirms** it (the exact version is vulnerable): the inferred finding closes with
  reason `superseded_by_credentialed`, and the credentialed finding carries the claim forward.
- If credentialed **refutes** it (the exact version is patched — the ADR-078 false-positive case,
  which is most of them on a maintained host): the inferred finding closes with reason
  `refuted_by_credentialed`. This is how the 16 → 0 on `.146`'s OpenSSH becomes visible as an
  *action* — sixteen inferred candidates closed as refuted, not sixteen findings silently vanishing.
- The two share the `(asset, package, cve)` identity but differ in source, so this is a source-aware
  supersession, not the ordinary dedup: a credentialed finding for a key closes any open inferred
  finding for the same key, and blocks a later inferred scan from reopening it while the credentialed
  read is current. Staleness applies — if the credentialed read ages out, the precedence lapses.

## Consequence

- No UI is built this session; this is the spec the console and the finding lifecycle implement when
  the production credentialed path lands (ADR-087's remaining fleet wiring). The `refuted_by_credentialed`
  and `superseded_by_credentialed` close reasons are new finding-lifecycle states to add then.
- The precedence direction here is the finding-level analogue of ADR-077's release-level rule (exact
  read outranks inference) and of ADR-081's decision (credentialed is correctness, not depth): where
  both exist, the exact one wins and the inferred one is resolved, never left standing beside it.
