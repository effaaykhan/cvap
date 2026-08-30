# ADR-009: Rule / VulnerabilityDef / VendorAdvisory are separate entities

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 modelled a single `Vulnerability` entity, implicitly CVE-shaped. Most of what the platform
will report has no CVE: DAST findings, API issues, configuration weaknesses and SAST results
have a rule and a CWE and nothing else. Meanwhile the authority for whether a distro package
is actually vulnerable is a vendor advisory, which is neither the CVE nor the detection logic.

## Decision

Four entities where v1 had two.

- **Rule** — detection logic, versioned, belonging to a signed rule pack. Always present on
  a finding. Carries `execution_site` (ADR-013), CWE, base confidence and evidence
  requirements.
- **VulnerabilityDef** — a CVE record: CVSS, KEV flag, EPSS score, CPE ranges. **Optional**
  on a finding. Many-to-many with rules in both directions via `RULE_VULN_MAP`.
- **VendorAdvisory** — USN, RHSA, DSA, MSRC and friends, with child
  `ADVISORY_FIXED_PACKAGE` rows giving the fixed version per distro release (ADR-014).
- **Finding** — the observed instance: asset, rule, instance locator, evidence, exposure set.

`FINDING.rule_id` is mandatory; `FINDING.vuln_def_id` is nullable.

## Alternatives considered

**Keep one `Vulnerability` entity and give non-CVE findings synthetic CVE-like IDs.**
Rejected: it puts fabricated identifiers into a field customers cross-reference against
external sources, and it still leaves nowhere to hang detection logic, CWE and confidence.

**Rule and VulnerabilityDef only, folding advisories into CPE ranges on the CVE.** Rejected
because it destroys exactly the information ADR-014 depends on: an advisory's fixed version
is per distro release and backport-aware, which a CVE's upstream version range cannot
express.

**A one-to-one rule-to-CVE mapping.** Simpler joins. Rejected in both directions: one rule
commonly detects a family of CVEs (a single vulnerable version banner), and one CVE is
commonly detected by several rules at different confidence levels (credentialed package
match versus banner inference). The many-to-many with `match_confidence` is the honest model.

## Consequences

Every finding is explainable by the rule that raised it, whether or not a CVE exists, and
DAST/SAST/config findings are first-class rather than second-class. Rule packs can version
and ship independently of CVE data (ADR-019). The cost is more joins on the finding read
path, a `RULE_VULN_MAP` whose confidence values need curation, and the discipline that
nothing may key off `vuln_def_id` being present.

## Review trigger

Revisit if a fifth content type appears that fits none of these — a threat-intelligence
indicator or a compliance control mapping is the likely candidate — rather than stretching
`Rule` to cover it.
