# ADR-106: A zero read from a column nobody writes is not evidence

**Status:** Accepted
**Date:** 2026-09-28
**Supersedes:** ADR-105's coverage figures — "of 6,021 CVEs ingested, 0 carry a CVSS vector and
0 are flagged `in_kev`". Every decision in ADR-105 stands: the five numbered decisions, the
rejected alternatives, and the conclusion that the layer ATT&CK hangs off is partial. What is
withdrawn is one of the two numbers it cited as evidence for that conclusion, and the instrument
both were read from.
**Follows:** ADR-069 (KEV/EPSS prioritisation — `kev` and `epss` are the source), ADR-105,
ADR-017 (the knowledge tables are global and untenanted), ADR-102 (the same shape: an ADR
written alongside its own code, stating things about it that were never measured).

## Context

ADR-105 named its own coverage problem with numbers, which was the right instinct. One of the
numbers was wrong, and it was wrong in a way that no reader of the ADR — including its author —
could have detected from the ADR.

The claim was `0 are flagged in_kev`. That is a true statement about the column
`vulnerability_defs.in_kev` and a false statement about the thing the column appears to measure:

```
kev rows                      1723
vulnerability_defs            6021
CVEs present in BOTH (join)      4
vulnerability_defs.in_kev = t    0
```

Four CVEs are in both tables. None was flagged, because **nothing has ever written that column.**
`knowledge/risk_ingest.py`'s `import_kev` writes the `kev` table and stops. The same is true of
`vulnerability_defs.epss_score`, which sat empty beside an `epss` table holding 378,567 rows. Both
columns predate ADR-069, which introduced `kev` and `epss` and named them the source — *"a CVE
absent from `kev` is **unlisted**, not known-unexploited"*. Every read path in the code followed
ADR-069: `findings.go`, `overview.go` and `assets.go` all `LEFT JOIN kev k ON k.cve_id = vd.cve_id`.
Nothing followed the columns.

So the columns were not stale, which is a recoverable condition that eventually shows up as
disagreement. They were permanently false and permanently null, and they read as authoritative:
`NOT NULL DEFAULT false`, a partial index carrying the comment *"risk ranking reads these two
together"*, and a line in the architecture ER diagram reading *"CISA known exploited"*. A reader
had no way to distinguish the column from a maintained field. Two readers did not:

- **ADR-105** cited the zero as evidence.
- **`priority_acceptance_integration_test.go`** justified "CVE-2012-2122 is not in KEV" with
  *"verified against the ingested feed: `in_kev=f`"*. The column also read `f` for CVE-2012-1823
  — the CVE that same test seeds INTO `kev` and asserts IS listed. The conclusion was correct and
  the instrument would have returned `f` whatever the truth was.

This is the defect the project has hit before under other names: a control that answers a
different question than the one being asked (ADR-102's §"the check that checked itself"), and a
gate that silently passes rather than failing. The reason this repository writes migrations that
assert what they believe rather than assume it is the same reason this ADR exists.

## Decision

**1. The zero is withdrawn; the conclusion is not.** Measured against `kev`, KEV coverage of the
ingested CVE set is **4 of 6,021**, not 0. ADR-105's argument — that the layer ATT&CK mapping
hangs off is already partial, and the mapped fraction will be lower still — is unaffected, because
4 of 6,021 is as partial as 0 of 6,021. The decision does not move. The evidence line does, and an
ADR whose evidence is wrong is worth correcting even when its conclusion survives, because the
next decision may lean on the number rather than on the conclusion.

**2. The CVSS-vector zero stands, on a different footing.** `vulnerability_defs.cvss_vector` is
genuinely empty — the USN feed publishes no CVSS vectors — and unlike `in_kev` no other table
contradicts it. It is an unfilled field rather than a wrong answer. It is kept, and it now carries
a `COMMENT ON COLUMN` saying it is unpopulated and read by nothing, so the next reader does not
have to rediscover this.

**3. A fact has one source.** `in_kev` and `epss_score` are dropped (migration 0049) rather than
populated. Populating means one fact maintained in two places by two importers that must both run
and must agree for ever, for a reader that does not exist. `kev` is keyed on `cve_id` and holds
1,723 rows; the join it would have saved costs nothing worth buying back. Where a dedicated feed
table exists, the denormalised copy beside it is deleted, not synchronised.

**4. Dropping a column asserts that it holds nothing.** Migration 0049 refuses the drop if either
column ever carries a row, so a later change that starts writing them fails the migration instead
of losing the data silently. Its down restores 0010's exact shape — a down that returns a looser
schema than it claims invites rows the up could not have produced.

**5. A number in an ADR names the table it was read from.** The failure here was not arithmetic.
It was that "0 are flagged `in_kev`" reads as a fact about KEV and is a fact about one column.
Coverage figures quoted in future ADRs state the query, so the instrument is reviewable alongside
the number.

## Rejected

**Editing ADR-105.** Accepted ADRs are superseded, never edited, and the `protect-contracts` hook
enforces it. The wrong number stays visible in ADR-105 with this ADR pointing at it; a reader who
finds the old figure first needs the correction to be discoverable from it, which silent editing
would prevent.

**Populating `in_kev` from `kev` at import time.** It would have made the flag true and left the
real defect — two sources for one fact — in place, with a new failure mode: an importer that runs
`import-kev` but not the USN import, or vice versa, leaves the flag disagreeing with the table
again. The four intersecting CVEs would have been flagged and the next reader would have trusted a
column that is correct only as long as two jobs keep agreeing.

**Treating this as a prioritisation bug and fixing the ranking.** There was no ranking bug. KEV
ordering was always computed from the `kev` table and is unchanged by the drop, which the
acceptance demonstrates: CVE-2012-1823 (KEV, CVSS 7.5, priority 1001000003) still ranks above
CVE-2007-2447 (non-KEV, CVSS 10.0, priority 710004). Reporting this as a KEV outage would have
been a second wrong statement about the same code.

**Leaving the column with a comment instead of dropping it.** A comment is read by whoever opens
the migration; the column is read by whoever writes a query. The evidence that a comment is not
enough is that the ER diagram already carried a description of this column — *"CISA known
exploited"* — and that description is what made it credible.

## Consequences

`vulnerability_defs` loses two columns and one index; `cvss_base` stays, and is the only CVSS
field with a reader. The ER diagram in `docs/architecture-v2.md` now draws `KEV` and `EPSS` as the
entities that hold these facts, annotated `joined on cve_id, NOT a FK`, rather than implying the
facts live on `VULNERABILITY_DEF`. The corrected instrument is recorded where the mistake was made
— in the test comment that cited it, and in `docs/phase-session-map.md` beside the original claim.

What this does not fix is the general case, and the general case was measured rather than
guessed. Of the 52 columns across the ten knowledge tables, six have no reader in production Go,
Python or TypeScript: `advisory_fixed_packages.fixed_pkg_id` and `rule_vuln_map.map_id` (surrogate
keys, which the database reads even where the code does not), and
`rule_vuln_map.match_confidence`, `vulnerability_defs.cpe_ranges`,
`vulnerability_defs.cvss_vector` and `vulnerability_defs.published_at`. None is dropped here.
`cpe_ranges` in particular is unread BY DESIGN — non-negotiable #5 and ADR-014 keep distro
packages matching vendor advisories rather than NVD version ranges, so an empty NVD fallback is
the invariant holding, not a gap. The others are unfilled fields with nothing contradicting them.

The rule this ADR establishes is therefore narrower than "delete unread columns", which would
have taken `cpe_ranges` with it: it is that where a table already answers a question, a column
beside it answering the same question is deleted, because only that shape can disagree.
