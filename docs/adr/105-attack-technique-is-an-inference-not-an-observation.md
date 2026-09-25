# ADR-105: An ATT&CK technique is an inference about a weakness, never an observation of an attack

**Status:** Accepted
**Date:** 2026-09-25
**Follows:** ADR-059 (advisory matching, the last scope expansion authorised this way), ADR-069
(KEV and EPSS as risk feeds), ADR-063 (the knowledge-import identity), ADR-013/050 (the
evaluator/rule split), non-negotiable #9 (detection establishes evidence without achieving impact).
**Scope:** MITRE ATT&CK mapping is not on the MVP's out-of-scope list and is not covered by any
existing ADR. This authorises it, the way ADR-059 authorised advisory matching.

## Context

An operator reading a finding wants to know what an adversary would DO with it — the tactic, the
technique, the ID they can hand to a detection engineer. CVAP has most of the raw material: 6,021
CVE definitions, a `cwe` column populated on 13 of 14 rules, KEV, and EPSS across ~378k CVEs.

What it does not have, and what nobody has, is an authoritative CVE-to-technique mapping. The
published sources are partial and disagree; the CWE -> CAPEC -> ATT&CK chain is many-to-many at two
hops; and every route is a statement about what an attacker COULD do, produced by someone reasoning
about a weakness. None of it is a record of anything happening.

That matters here more than it would elsewhere, because this scanner's whole posture is that a
claim carries its evidence. Non-negotiable #9 says detection establishes evidence without achieving
impact — CVAP deliberately never exploits anything, so it is in no position to report how something
was exploited. A console that prints "T1190" beside a finding is one design decision away from
being read as "this host was attacked this way".

## Decision

**1. ATT&CK is a knowledge feed, on the same terms as the others.** A pinned corpus version
ingested by `cvap_knowledge_import` (ADR-063), provenance and freshness recorded in
`knowledge_feed_status`, no tenant scope — techniques are global facts, like `vulnerability_defs`.
New tables hold the technique catalogue and the mappings; the mapping rows carry their SOURCE and
that source's own confidence, never a number this project invents.

**2. Two anchors, because findings have two shapes.** Non-negotiable #4: a finding carries a
`rule_id` always and a `vuln_def_id` optionally.

- `vuln_def -> technique`, from a published CVE-to-ATT&CK dataset. Covers advisory findings.
- `rule -> technique`, curated per rule and stored against the rule. Covers evaluator findings,
  which have no CVE at all. Fourteen rules is a hand-curatable number; six thousand CVEs is not,
  which is exactly why the two anchors are different in kind.

**3. A technique is rendered as an INFERENCE and labelled as one.** The API field says what it is
and what produced it; the console never presents a technique as something observed. The wording is
part of the contract, not a UI preference: this is the same rule that makes a seen-only port read
"open, unidentified" rather than as a service (ADR-103).

**4. Coverage is stated, not implied by absence.** A finding with no mapped technique reads
"unmapped", and the surface reports what fraction is mapped. Silence would say "no technique
applies", which is a different and stronger claim than "we have no mapping".

**5. ATT&CK does NOT feed prioritisation.** KEV is observed exploitation and EPSS is a measured
probability; both already rank findings on evidence. Adding an inference to that score would
launder a guess into a number and double-count the same weakness. Technique is context for a
human, not an input to severity.

## Alternatives considered

**CWE -> CAPEC -> ATT&CK as the primary source.** Two many-to-many hops. Applied across thousands
of CVEs it produces plausible-looking output at a volume nobody can check, which is the worst
failure mode available — wrong in a way that reads as thorough. Kept only as the RULE anchor, where
a person curates fourteen decisions and owns each one.

**Inferring technique from an open port or service** — RDP exposed implies T1021.001, and so on.
Rejected. It is a statement about what an adversary might do, attached to a host as if it were a
property of that host. On the estate this was designed against it would have attached techniques to
the 2000/5060 rows that a middlebox answered for addresses which do not exist.

**Generating mappings with a language model.** Rejected: not reproducible, not auditable, and not
diffable in CI. Every other knowledge feed here can be re-fetched and compared; this one could not.

**Mapping at the finding level.** Rejected — it would duplicate the same mapping per tenant per
asset. The mapping is a property of the weakness, so it lives with the definition.

## Consequences

A finding can carry tactic, technique and ID, with a link and a named source, and a detection
engineer gets something actionable without CVAP pretending to have watched an intrusion.

The cost is coverage, and it will be visibly low at first. Measured while writing this: of the
6,021 CVEs ingested, **0 carry a CVSS vector and 0 are flagged `in_kev`** — the USN feed does not
supply vectors, and the KEV catalogue's 1,723 entries do not intersect this advisory set. The layer
ATT&CK would hang off is itself partial, so the mapped fraction will be lower still. Decision 4 is
what keeps that honest rather than embarrassing.

A new feed also means a new way to go stale, and ATT&CK is worse than most: techniques are
deprecated, renamed, and split into sub-techniques between versions. The corpus version is pinned
and recorded per mapping row, and a technique that disappears from a later version is retired with
its history rather than deleted — a finding that cited T1234 last quarter must still explain itself.

## Review trigger

Revisit when a technique starts carrying weight it cannot bear: the first time one is used to
prioritise work, to drive a customer-facing report, or to justify a decision. Revisit decision 1 if
a sound CVE-to-technique source with broad coverage appears, and decision 5 if evidence emerges
that technique adds ranking signal beyond what KEV and EPSS already measure. Revisit the whole ADR
at the next ATT&CK major version, when the deprecation path is exercised for real.
