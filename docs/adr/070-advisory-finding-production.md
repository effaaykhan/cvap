# ADR-070: Advisory findings — turning a match into a finding, and the model that carries it

**Status:** Accepted
**Date:** 2026-09-09

P3.3's last link (ADR-059/060/064). S27–S31 built and validated the chain that decides whether an
installed version is affected — comparators (ADR-062), advisories (ADR-063), release resolution
(ADR-064), coverage (ADR-067). This ADR turns that **verdict into a finding**: the step that was
missing, not a fix to a working one.

## Context — a path that never ran

The advisory matcher's decision logic (`FixesFor` → `version.SchemeByName` →
`AffectedRange.Vulnerable`) was real and validated against a real host's real version
(`TestAdvisoryMatchInSitu`), but it lived **only in a test**. No production path called it:

- `internal/correlate/findings.go` produces findings from the **rule engine** only
  (`rules.Evaluate`); it never consulted the advisory matcher.
- The release path stopped at `SetRelease` — it wrote `distro_release` and never matched.
- `store.Finding` had no `vuln_def_id` field and `Upsert` never wrote the column. The plumbing to
  carry a CVE to a finding row did not exist.

The consequence compounded: `AdvisoryStatusInputs` computes `hasAdvisoryFinding` as
`EXISTS(... f.vuln_def_id IS NOT NULL)`, which was never true, so the entire ADR-067/068 state
machine could only ever emit `no_release`/`clean`/`cannot_know` — **never `vulnerable`**. The B29
coverage work (S33) landed correctly on top of a `vulnerable` state production could not reach.

This is the write-carry-store-drop shape on the exact field P3.4 orders by — except worse: the
producing path was absent, not merely dropping a write.

## Decision

After release resolution, in the **same correlation transaction** (ADR-006: the moment the derived
model changed is the moment to re-judge it), match each resolved service's product+version against
the advisory keyspace and raise a finding per matched CVE. Gather in the store, decide in Go
(ADR-062: SQL narrows, Go compares versions). Four modelling decisions, each settled below.

### 1. Dedup key: `(asset, package, cve)` — the package, not the port

An advisory finding's claim is about an **installed package**, not a network endpoint. A host
running one vulnerable `mysql-dfsg-5.0` behind two ports has **one** vulnerability, not two — so the
dedup key is `advisory|{asset_id}|{package}|{cve}`, the credentialed-host shape in ADR-010's table
(asset, component identity, rule), **not** the network shape (asset, port, protocol, rule). The
`instance_locator` is the package name, and exposure is the union of the zones the service was seen
from — the finding is one, exposed from wherever the package answers.

### 2. `source = 'network'`, and why — with medium confidence

`source` names **how the evidence was obtained**, and it was an **unauthenticated network banner**
— so `network`, not a new `advisory` value (source is a collection taxonomy, and "advisory" is a
*matching* method over network-collected evidence, not a way of collecting it). This is deliberately
in tension with the package-shaped dedup, and the tension is the honest signal: a network-collected
claim about a package is **banner-inferred**, so its confidence is banner-level (**medium**, ADR-014
— "banner-derived version inference is medium at best"), never the high of a credentialed read. To
an analyst the finding reads: *we saw this version over the network and it is below the advisory's
fix; confirm against the installed package.* Phase 4 credentialed assessment re-raises the **same
package claim** at `source = 'credentialed'` and high confidence, from the package manager's
authoritative installed version — the dedup key is shared, so the credentialed finding supersedes
the banner one rather than duplicating it.

### 3. One rule, CVE in `vuln_def_id` (ADR-009's split)

A finding carries a `rule_id` always (ADR-009, non-negotiable #4). Advisory findings hang on **one** seeded rule —
`advisory-version-match` — not one rule per advisory: the rule is the **detection logic** ("an
installed package version is at or below an advisory's fixed version, compared with the comparator
the advisory names"), and the **CVE is the `vuln_def_id`**. That is exactly ADR-009's Rule /
VulnerabilityDef split — the rule is stable and the CVE varies per finding. The rule is a new
`engine = 'advisory'` kind (migration 0038, additive `ALTER TYPE`), `execution_site = 'core'`
(evidence-based, correctable retroactively). It is a distinct mechanism from the closed rule-engine
evaluators (ADR-050), so the rules loader — which filters `engine = 'rules'` — never feeds it to the
wrong engine; it exists to satisfy `rule_id`-always and to carry the CWE/severity/remediation the
finding reads.

### 4. Reach is bounded, and the ADR says so

The first advisory findings are **not complete coverage**, and must not be read as such:

- **B28 bounds which services can be matched at all.** Matching needs a product **and a version**
  from the banner, and a product→package mapping (`product_packages`, ADR-064). On Metasploitable
  only ~2 services band-vote a release and carry a version in safe mode; the rest yield no version,
  so no match is attempted — *absence of a match here is absence of a version, not evidence of
  safety* (the same absence-is-not-evidence discipline).
- **B30 bounds what a clean result means within a covered release.** The keyspace holds packages
  that were **advised**, not packages that **shipped**; a product mapping to several candidate
  packages is matched against each, and a release that never carried a package returns no fix for
  it. So a no-match on a covered release is "no known advisory among advised packages", which
  ADR-068's `advisory_status = clean` already states as its honest, narrower meaning.

These are not deferred to a footnote: the finding list will carry real advisory findings for the
services the banner set covers, and silence for the rest is a coverage gap (B28), never a clean
verdict.

## Consequences

- `store.Finding` gains `VulnDefID`; `Upsert` writes `vuln_def_id` and takes `source`. No new table.
- `internal/correlate` gains `evaluateAdvisories`, wired into `resolveHost` after release
  resolution, in the same transaction. Gather (`FixesFor`, `PackagesForProduct`, `AdvisoryVulnDefs`)
  is store I/O; the version verdict is `internal/version` (Go authoritative, ADR-062).
- Migration 0038 adds the `advisory` engine kind; migration 0039 seeds the `advisory-version-match`
  rule into the builtin pack. They are split because Postgres forbids using a new enum value in the
  transaction that added it. `engine_kind` gains a value used only Core-side; nothing dispatches it
  to a scan point.
- The `vulnerable` advisory_status (ADR-068) becomes reachable in production for the first time.

## Acceptance

This session stops at **real advisory findings existing on Metasploitable** — not at ordering them
(P3.4, next session, deliberately built on findings this path already produces rather than on a
same-session matcher). The acceptance seeds USN-1467-1 (CVE-2012-2122, hardy, `mysql-dfsg-5.0`,
fixed `5.0.96-0ubuntu3`, dpkg) through the import role and an asset resolved to hardy carrying a
`MySQL 5.0.51a-3ubuntu5` service — the advisory and the version are the real feed's and the real
host's (`TestAdvisoryMatchInSitu`'s data). The matcher must raise a finding with
`vuln_def_id → CVE-2012-2122`, `source = 'network'`, dedup `advisory|{asset}|mysql-dfsg-5.0|
CVE-2012-2122`, and evidence carrying the banner, the advisory ref, the fixed and installed
versions, and the comparator — verifiable by hand without re-scanning. If the path works there are
real findings; if it does not, that is this session's finding.
