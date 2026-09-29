# Rendering ATT&CK techniques in the console

**For:** whoever builds the ATT&CK console work in `.worktrees/ui`.
**Contract:** ADR-105. **API:** shipped and live — every field below is already served
and typed in `src/api/schema.ts`. Nothing here needs backend work first.

This is a spec, not a design. Layout, placement and visual treatment are yours. What is
fixed is the *wording contract* — ADR-105 decision 3 puts it in the API rather than the
UI deliberately, so this document is the reason, not an instruction to follow blindly.

---

## 1. The one thing that must not go wrong

**CVAP has never observed any of these techniques being used, and cannot.**
Non-negotiable #9: detection establishes evidence without achieving impact — no
exploitation, no shells, no data extraction. A technique here is an *inference about a
weakness*: someone's reasoning about what an adversary COULD do with it.

A console that prints `T1190` beside a finding is one design decision away from being
read as *"this host was attacked this way"*. That is the failure this whole feature is
shaped to avoid. Every technique carries `inference: "inferred"` for exactly this
reason — it is a constant, and it is a field rather than documentation so that a client
rendering what the API sends says the right thing without having read the ADR.

So: **never** render a technique with wording that implies observation. Not
"detected", "seen", "used", "exploited via", "attacker used". Prefer "would enable",
"an adversary could", "inferred technique". If in doubt, the word `inferred` is in the
payload — show it.

## 2. The second thing: an empty list is not "no technique applies"

`attack_techniques` is **always present** and is `[]` when CVAP holds no mapping. It is
deliberately not `omitempty`: a field that vanishes when empty cannot be told apart from
a field the client forgot to read, and the distinction is the whole of ADR-105
decision 4.

Empty means **"CVAP holds no mapping for this finding."** It does *not* mean no
technique applies. Render it as `unmapped` or equivalent wording — never as blank space,
never as an absent row, never as a dash that reads like "none".

There is a third state that looks identical from a single finding and is completely
different: **no ATT&CK catalogue has been ingested at all**, so nothing anywhere can be
mapped. You do not have to detect this yourself — the API tells you (§4).

## 3. Finding list and finding detail

`GET /v1/findings` and `GET /v1/findings/{id}` both carry:

```ts
attack_techniques: TechniqueResponse[]          // always present, [] = no mapping held
attack_technique_coverage?: {                    // list and detail both
  findings: number
  mapped: number
  statement: string                              // render this verbatim somewhere
}
```

### `TechniqueResponse`, field by field

| field | type | notes |
|---|---|---|
| `id` | `string` | `T1040`, or a sub-technique like `T1190.001`. The thing a detection engineer wants. |
| `name` | `string` | `Network Sniffing`. |
| `tactics` | `string[]` | ATT&CK tactic shortnames, e.g. `credential-access`, `discovery`. A technique serves one or more. |
| `url` | `string?` | The MITRE page. Link the id to it. |
| `inference` | `string` | Always `"inferred"`. See §1. |
| `anchor` | `string` | `"rule"` or `"cve"` — **see below, these are not the same weight** |
| `source` | `string` | `cvap-curated` or `ctid-mappings-explorer`. Who made the claim. |
| `rationale` | `string?` | Present on the **rule** anchor only: the curator's written reason. Worth surfacing — it is the argument, not a label. |
| `comments` | `string?` | Present on the **cve** anchor only: the published source's own note. |
| `mapping_type` | `string?` | CVE anchor only, the source's OWN qualifier: `exploitation_technique`, `primary_impact`, `secondary_impact`. Carry it verbatim; do not translate it into a confidence. |
| `confidence` | `number \| null?` | The **source's** confidence. Currently `null` for every ingested source, because none publishes one. If it is absent, show nothing — do not substitute a number, a bar, or a "high/medium/low". |
| `deprecated` | `boolean?` | The technique has been retired from the pinned corpus. **Still render it** — see §5. |
| `revoked_by` | `string?` | The technique that replaced a retired one. |

### The two anchors carry different weight

This is ADR-105 decision 2 and it matters for how you present them:

- **`anchor: "rule"`** — a judgement a person here made about that specific detection
  rule, with a written `rationale` they own. Curated, reviewable, ours.
- **`anchor: "cve"`** — a third party's judgement about the CVE, from a published
  dataset, with that dataset's own `mapping_type` qualifier.

They are not interchangeable evidence. An analyst deciding how much weight to give a
technique needs to know which one they are holding. Distinguishing them visually is
yours to design; collapsing them into one undifferentiated list is the thing to avoid.

## 4. The knowledge surface

`GET /v1/knowledge/freshness` gained an `attack` object beside `feeds` and `coverage`:

```json
{
  "catalogue_version": "16.1",
  "techniques": 799,
  "deprecated": 143,
  "cve_mappings": 1183,
  "mapped_cves": 419,
  "local_cves": 6028,
  "local_mapped_cves": 0,
  "curated_rules": 11,
  "total_rules": 14,
  "statement": "No ingested CVE carries a mapping: the published dataset covers CISA KEV, ..."
}
```

**`mapped_cves` vs `local_mapped_cves` is the pair that matters.** The first is what the
published dataset covers in total (419). The second is how many of *this installation's*
CVEs are among them — currently **0**. Both are true; only the second answers "will my
advisory findings show a technique?". Showing `1183 mappings ingested` on its own reads
as coverage that does not exist.

Render `statement` verbatim. It names which of these states the installation is in, and
each needs a different action from the operator:

- nothing ingested → run `make knowledge-attack`
- catalogue in, mappings missing → run `make knowledge-attack-mappings`
- both in, overlap genuinely empty → nothing to fix; this is a measured fact
- both anchors live → normal

The two feeds also appear in the existing `feeds` array as `mitre-attack` and
`mitre-attack-cve`, with the same `current`/`stale`/`never` state as USN, KEV and EPSS.
They need no special handling — whatever the freshness panel already does will work.

## 5. Retired techniques are shown, not hidden

ADR-105's retirement rule: a technique that disappears from a later corpus is **retired
with its history, never deleted**, because a finding that cited `T1234` last quarter must
still be able to explain itself. `deprecated: true` arrives on exactly those.

Filtering them out would silently strip an older finding's only reason. Mark them —
acting on a technique the current corpus has withdrawn is a different decision from
acting on a current one, and nothing else on screen would say so. `revoked_by` names the
replacement when there is one.

## 6. What techniques must NOT do

**They do not feed priority.** ADR-105 decision 5. KEV is observed exploitation and EPSS
is a measured probability; both already rank findings on evidence. Adding an inference to
that score would launder a guess into a number and double-count the same weakness.

So: do not sort by technique, do not weight a finding up for having one, do not colour a
row by tactic severity, and do not let "has techniques" imply "more urgent". The existing
`priority_basis` and the KEV/EPSS fields stay the ranking story. Technique is context for
a human, and it sits beside the ranking rather than inside it.

## 7. Current data, so you can see it working

As of 2026-09-29 on the dev database, two real findings carry techniques:

```
plaintext-telnet  23/tcp   T1040 Network Sniffing        (credential-access, discovery)
                           T1557 Adversary-in-the-Middle (credential-access, collection)
plaintext-ftp     21/tcp   T1040, T1557
```

Both `anchor: "rule"`, `source: "cvap-curated"`, each with a full `rationale`.

**Every other finding will be `[]`** — 11 of 14 rules are curated, and the CVE anchor is
currently empty for the reason §4's statement gives. That is the normal case, not an
error, and it is the case most worth designing for.

Three rules are deliberately uncurated and will always be `[]` until someone curates
them: `advisory-version-match` (its findings carry a CVE, so the CVE anchor is its
route), `tls-certificate-expiring-soon` (a forecast, not a present weakness), and
`http-missing-security-headers` (the honest technique would describe what happens to a
visitor, which is a different asset).

## 8. Types

`src/api/schema.ts` is already regenerated and typechecks. You may want aliases in
`src/lib/api.ts`, matching the existing pattern there:

```ts
export type Technique = Schemas["TechniqueResponse"];
export type TechniqueCoverage = Schemas["TechniqueCoverageResponse"];
export type AttackCoverage = Schemas["AttackCoverageResponse"];
```

Note `FindingSummary` now has a **required** `attack_techniques` field, so any fixture
constructing one needs `attack_techniques: []`. The shared factory in
`src/lib/console.test.ts` has already been updated.

## 9. How to tell it is right

- A finding with no mapping reads as *"no mapping held"*, never as blank and never as a
  verdict that nothing applies.
- No wording anywhere implies CVAP watched an attack.
- A curated technique and a CVE-dataset technique are visibly different things.
- A retired technique still appears, marked.
- Nothing about techniques changes the order of the finding list.
- The knowledge panel shows `local_mapped_cves` and not just `cve_mappings`.
- With a catalogue that has never been ingested, the panel says so and says what to run.

## 10. Reference

- `docs/adr/105-attack-technique-is-an-inference-not-an-observation.md` — the decisions
  and, importantly, the alternatives that were rejected and why.
- `internal/control/api/techniques.go` — response types, the statement wording, and the
  comments explaining each choice.
- `internal/store/CLAUDE.md`, section "An ATT&CK technique is an inference" — the read
  path's contract.
- `/v1/findings.csv` already carries `attack_techniques_inferred`,
  `attack_technique_names` and `attack_technique_sources` if you want a worked example of
  the same contract surviving a format with no room for a statement.
