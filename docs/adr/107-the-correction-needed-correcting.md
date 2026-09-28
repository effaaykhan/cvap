# ADR-107: The correction needed correcting — an ADR about instruments, measured with a bad one

**Status:** Accepted
**Date:** 2026-09-28
**Supersedes:** ADR-106's evidence — its column-readership count, the query block it displays,
one citation, and the scope of its own Supersedes clause. Every decision in ADR-106 stands:
the zero is still withdrawn, the CVSS-vector zero still stands on its own footing, a fact still
has one source, 0049 still asserts the columns are empty before dropping them, and a coverage
figure still names its query. What changes is that ADR-106 did not obey its own decision 5.
**Follows:** ADR-106, ADR-105, ADR-069, ADR-102 (the nearest precedent: an ADR written alongside
its own code, stating unmeasured things about it).

## Context

ADR-106 exists because a zero was read from `vulnerability_defs.in_kev`, a column no importer
writes, and quoted as a fact about KEV. Its decision 5 says coverage figures in future ADRs must
state the query they came from, so the instrument is reviewable beside the number.

ADR-106 then quoted three figures of its own without stating a query, and one of them was
produced by an instrument with the same defect it had just described. This is not irony worth a
sentence; it is evidence that the failure is easy rather than careless, which is the part worth
recording.

### 1. "Six of 52 columns have no reader" is an undercount

The 52 is right. The six is not, and it was reached twice by two variants of the wrong
instrument: a search for each column's NAME as a word. That clears a column whose name is
distinctive and silently passes any column whose name is an ordinary English word appearing
elsewhere — `title`, `description`, `vendor`, `severity` — so the method returns exactly the
columns it can see and reports them as the columns that exist.

The right instrument for aliased SQL is the qualified reference. Production Go touches these
tables in `internal/store/{advisories,assets,findings,overview}.go` and
`internal/control/api/handlers_{assets,knowledge}.go`:

```
$ grep -rn 'vd\.' --include=*.go internal/ | grep -v _test | grep -o 'vd\.[a-z_]*' | sort | uniq -c
     17 vd.cve_id
      8 vd.cvss_base
     12 vd.vuln_def_id

$ grep -rn 'va\.' --include=*.go internal/ | grep -v _test | grep -o 'va\.[a-z_]*' | sort | uniq -c
      3 va.advisory_ref
      3 va.issued_at
```

Against what `knowledge/usn_ingest.py` writes (`vendor_advisories (advisory_ref, vendor,
issued_at)` at :202, `vulnerability_defs (cve_id, title)` at :208):

| column | written | read |
|---|---|---|
| `vulnerability_defs.title` | yes | **no** |
| `vulnerability_defs.description` | no | **no** |
| `vulnerability_defs.cvss_vector` | no | **no** |
| `vulnerability_defs.cpe_ranges` | no | **no** |
| `vulnerability_defs.published_at` | no | **no** |
| `vendor_advisories.vendor` | yes | **no** |
| `vendor_advisories.severity` | no | **no** |
| `vendor_advisories.distro_release` | no | **no** |
| `rule_vuln_map.match_confidence` | no | **no** |
| `rule_vuln_map.map_id` | PK | **no** |
| `advisory_fixed_packages.fixed_pkg_id` | PK | **no** |

**At least eleven, not six** — and "at least" is the honest quantifier, because the remaining
tables (`kev`, `epss`, `release_coverage`, `product_packages`, `knowledge_feed_status`) were
cleared by the same name-grep that failed here and have not been re-checked column by column.
A number this ADR cannot stand behind is stated as a bound rather than rounded into a fact.

### 2. The displayed query block does not reproduce

ADR-106 shows `1723 / 6021 / 4` as a bare result with no query. Measured today against the same
database, the obvious reading of it gives `1723 / 6028 / 5`:

```sql
select count(*) from kev;                                             -- 1723
select count(*) from vulnerability_defs;                              -- 6028
select count(*) from vulnerability_defs vd join kev k using (cve_id);  --    5
select count(*) from epss;                                            -- 378567
```

The gap is test fixtures. The dev database is shared, the knowledge tables are global and
untenanted by design (ADR-017), and every integration fixture that needs an advisory writes a
permanent row into them. Six `vulnerability_defs` rows are reachable only from a `TEST-`
advisory, and the exclusion ADR-106 relied on but never wrote down is:

```sql
-- feed-derived only: 6022 defs, 4 of them in KEV  (2026-09-28)
SELECT count(*) FROM vulnerability_defs vd
 WHERE EXISTS (SELECT 1 FROM advisory_vuln_map m JOIN vendor_advisories va USING (advisory_id)
                WHERE m.vuln_def_id = vd.vuln_def_id AND va.advisory_ref NOT LIKE 'TEST-%');
```

The fifth intersecting row is **CVE-2012-1823** — the CVE ADR-106 uses three times as its
KEV-listed example, seeded into `kev` by `priority_acceptance_integration_test.go`. A reader
re-running the stated query finds the ADR's own headline CVE sitting in the row the ADR does not
account for. That is the whole failure mode of decision 5 in one row.

### 3. A citation that cannot be followed

ADR-106 attributes to ADR-102 a section called §"the check that checked itself". ADR-102 has no
such section — its headings are §1 through §7, and the word "itself" does not appear in the file
at all. The nearest real one is §6, "Why the original review missed all of this". An
unfollowable citation in an ADR whose thesis is that evidence must be checkable.

### 4. The Supersedes clause names the weaker of two false claims

ADR-106 quotes ADR-105's "0 carry a CVSS vector and 0 are flagged `in_kev`". ADR-105's very
next clause is `105:83`:

> …and the KEV catalogue's 1,723 entries **do not intersect this advisory set**.

That one is unconditionally false — it is a claim about two tables, and they intersect on four.
"0 are flagged `in_kev`" is at least a true statement about a column. ADR-106 corrects the
weaker claim by name and the stronger one only by implication, so a reader diffing its
Supersedes header against ADR-105 finds an uncorrected false sentence immediately after the
corrected one.

### 5. What the re-measurement found that nobody had stated

`vulnerability_defs.cvss_base` is non-null on **2 of 6,028** rows, and both are fixtures:

```sql
select cve_id, cvss_base from vulnerability_defs where cvss_base is not null;
--  CVE-2012-1823 | 7.5      (TEST-PHP)
--  CVE-2007-2447 | 10.0     (TEST-SAMBA)
```

`usn_ingest.py` never writes `cvss_base`. So **no feed-derived CVE carries a CVSS score of any
kind** — not a vector, and not a base. ADR-105 said "0 carry a CVSS vector", which is true and
understates it: the priority packing's CVSS fallback term, `coalesce(e.score,
vd.cvss_base/10.0)` (`findings.go:570`), is dead on every real finding, and EPSS carries
prioritisation alone. ADR-106 kept `cvss_base` on the grounds that it "has a real reader" —
true, and the reader reads NULL on all 6,022 feed rows.

## Decision

**1. The figures are restated with their queries and a date.** As of 2026-09-28 on the dev
database: `kev` 1,723; `epss` 378,567; `vulnerability_defs` 6,028 of which 6,022 are
feed-derived; KEV intersection 5 overall and **4 feed-derived**. ADR-106's "4" was right about
the feed and its "6,021" and bare block were not reproducible. The conclusion is untouched
across every variant: coverage is a handful out of six thousand.

**2. Any figure read from a shared dev database states its fixture exclusion.** The knowledge
tables are global and untenanted (ADR-017) and integration fixtures write permanent rows into
them, so a bare `count(*)` over them measures the test suite as well as the feed. Decision 5 of
ADR-106 is extended: a coverage figure names its query *and* says whether fixtures are in it.

**3. "Has no reader" is not established by searching for a column's name.** It is established
by the qualified references in the SQL that reads the table, cross-checked against what the
importer writes. Where neither has been done, the claim is a bound ("at least eleven"), not a
count. This generalises past columns: a name-grep answers "does this string appear", and a
string appearing is not a fact about the code.

**4. Nothing further is dropped.** Eleven unread columns does not become eleven drops. ADR-106's
rule is unchanged and still selects exactly two: a column is dropped where another table already
answers the same question, because only that shape can disagree. `title`, `vendor`,
`cpe_ranges` and the rest are unfilled or unused, contradicted by nothing, and `cpe_ranges` is
unread BY DESIGN (non-negotiable #5, ADR-014). `cvss_base` stays despite reading NULL on every
feed row — it has a genuine reader and a genuine writer in the fixtures, and the feed not
supplying it is a coverage fact, not a schema one.

**5. The CVSS gap is recorded as a coverage fact, not fixed here.** That no feed-derived CVE
carries a CVSS score is worth knowing before anything is built on the CVSS term. Making the
importer populate it is a change to what CVAP ingests and belongs in its own decision.

## Rejected

**Editing ADR-106.** It is committed, and `.claude/hooks/protect-contracts.py` is explicit that
"a committed Accepted ADR has no override of any kind"; the single permitted edit is the Status
line via `CVAP_SUPERSEDE_ADR`, which `verify-contracts.py` then diffs. The commit was local and
unpushed and nobody had read it, which is the argument for amending it — and the argument was
put to the operator rather than taken, because a freeze that bends when the author judges the
audience small is not a freeze. The wrong figures stay visible in ADR-106 with this ADR pointing
at them, which is the property the rule buys.

**Treating this as too small for an ADR.** A miscount and a bad citation are small. The reason
they are here is that ADR-106 is the document establishing how figures get quoted, and a rule
whose founding document violates it teaches the exception rather than the rule. The chain
101→102, 103→104, 105→106→107 is the honest cost of writing decisions down while the work is
still moving.

**Re-deriving an exact unread-column count.** It would need a per-table audit of five more
tables to turn "at least eleven" into a number, and the number is not load-bearing — decision 4
does not depend on it. Stating a bound that is true beats spending the effort to state a figure
that would be quoted later as though it were checked.

## Consequences

ADR-105's index Status now carries the ADR-106 annotation, so a reader who meets the original
figure first can reach the correction — the discoverability ADR-106 argued for and did not
land. ADR-106's index row is corrected where it misreported the join (`findings.go`,
`overview.go` and `assets.go` all join `kev`; only `findings.go` joins `epss`).
`docs/architecture-v2.md` §8.4's prose entity description, which still listed the dropped
columns one section above the ER diagram that had been fixed, now matches.

What is still not measured: the five knowledge tables cleared only by the failed instrument, and
whether the `TEST-` fixture rows accumulating in the shared dev database's global tables should
be swept between runs. Both are named here so the next figure quoted from that database starts
from a known position rather than from a bare `count(*)`.
