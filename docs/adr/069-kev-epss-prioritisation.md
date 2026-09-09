# ADR-069: KEV/EPSS prioritisation — KEV dominates, absence is not a low value

**Status:** Accepted
**Date:** 2026-09-09

P3.4 (ADR-059). Ingest CISA KEV and FIRST EPSS and order the finding set by priority. This ADR
fixes the model before the scoring code.

## Context

Severity alone (CVSS) is a poor sort. CVSS scores a vulnerability's badness in the abstract; it
says nothing about whether anyone exploits it. KEV says someone *is* exploiting it in the wild;
EPSS estimates how likely exploitation is to start. A KEV-listed CVE on a reachable asset
outranks a higher-CVSS finding nobody has ever exploited — and that **inversion is the whole
point**: the finding list has, until now, only ever sorted by severity.

## Decision

### Priority is a lexicographic order (execution-plan §3.3), KEV first

A finding's priority is the tuple, highest-first:

1. **KEV-listed** — the CVE is in CISA KEV. Dominant: a KEV finding outranks any non-KEV
   finding regardless of CVSS. This single key produces the inversion.
2. **Internet-reachable** — exposure. *(Weak input, see below.)*
3. **Asset criticality**.
4. **EPSS**, preferring the empirical signal, falling back to CVSS where EPSS is unscored — see
   the absence rule.
5. **Finding severity** — always present, the final deterministic tiebreak.

Computed as a single `priority_score` (a bit-packed encoding of the tuple) so the finding list
keyset-paginates on `(priority_score DESC, finding_id DESC)`. The packing weights KEV above the
sum of every lower term, so no CVSS or EPSS value can lift a non-KEV finding above a KEV one —
the inversion is structural, not a matter of tuned weights.

### Absence is not evidence — the fifth application

- **KEV**: a CVE absent from `kev` is **unlisted**, not known-unexploited. It receives no KEV
  boost, and it is never labelled "not exploited" — only "not listed". Not being in KEV is the
  absence of a signal, which is how a boolean-first lexicographic order already treats it (it
  falls through to the remaining keys), so absence carries no penalty, only no boost.
- **EPSS**: a CVE with no `epss` row is **unscored**, not probability 0. It is represented as
  `null`, never coalesced to 0, and shown as "unscored". A missing EPSS must not demote a finding
  as if it were low-probability, so the long-tail key is `COALESCE(epss, cvss/10)` — an
  unscored-EPSS finding is ranked by the severity we *do* know (its CVSS), never dropped to the
  bottom for lacking a score. Only a finding with **neither** EPSS nor CVSS is genuinely
  no-signal; it falls to the severity tiebreak and is flagged.
- **CVSS**: likewise nullable; unknown is shown as "unknown", never 0.

This is the fifth time the project applies *absence is not evidence*: no advisory for a package;
no keyspace analogue for a product (ADR-064); no labelled corpus instance for a rule (§5.5); no
advisory coverage for a release (ADR-067); and now no KEV/EPSS signal for a CVE.

### The exposure input is weak, and the model says so

Exposure is `internet_reachable`, which is zone-derived and largely **unwritten** (backlog #6:
the authoritative column was dropped, the read derives from `zone_type`). So today the exposure
key rarely discriminates — most findings read internal/unknown — and the order degrades in
practice to **KEV > criticality > EPSS/CVSS**. The model is correct and consumes exposure as the
second key by design (ADR-059's "KEV × internet-reachable × EPSS"); it is stated here that the
input is thin until #6 lands, rather than pretending the exposure signal is better than it is. A
finding whose exposure is unknown is not ranked as "internal" — unknown exposure is its own value.

### What the finding carries, and what the UI shows

Each finding surfaces its priority components, so the order is legible and never a black box:
`kev` (bool) + `kev_ransomware` + `kev_date_added`; `epss` (`null` = unscored) + `epss_percentile`;
`cvss` (`null` = unknown); and `priority_basis` — the dominant reason it sits where it does
("KEV-listed", "EPSS 0.97", "CVSS 9.8", or "unscored"). No coarse tier label with magic cutoffs:
the lexicographic order plus the visible KEV badge and raw EPSS/CVSS convey priority without a
fabricated bucketing. The finding list sorts by priority by default — its first meaningful order.

### Feeds and freshness (requirement 1)

`kev` and `epss` are ingested by `knowledge/risk_ingest.py` on the P3.2/P3.3 pattern: `fetch`
(online → pack) and `import` (offline, ADR-019) separably, provenance recorded, freshness in
`knowledge_feed_status`. EPSS updates daily, so its staleness threshold is **2 days** (tighter
than USN's 7); KEV's is **7 days**. Both surface in the knowledge panel beside USN.

### Bounds that refuse, not truncate (requirement 2)

EPSS is every published CVE (~370k rows today), far over USN's caps. Raised deliberately, stated:
`MAX_EPSS_ROWS = 1,000,000` (headroom over ~370k; a larger body is a refusal, not a truncated
import — a truncated risk feed is the silent under-reporting P3.1 was ordered first to prevent),
and a decompressed-size cap of `128 MB` guards a gzip bomb (EPSS ships gzipped, ~2.6 MB → ~11 MB).
KEV (~1700) is well within the existing caps. At any cap the whole fetch is refused.

## Consequences

- `kev` and `epss` are the 8th and 9th knowledge tables `cvap_knowledge_import` writes, and the
  17th and 18th the v2 ERD does not draw — recorded in the store `CLAUDE.md`, folded into B27.
- The prioritisation attaches to findings that carry a CVE (`vuln_def_id` → `cve_id`). Producing
  advisory findings from a match is not yet wired (a P3.3 remainder bounded by B28/B30); until it
  is, the CVE-bearing findings the model orders are seeded for the acceptance. The model is ready
  for the advisory→finding link the moment it lands — nothing about it assumes seeded data.

## Acceptance

On a real host, the finding set orders by priority, not severity: a KEV-listed CVE ranks above a
higher-CVSS one that is not. CVE-2012-2122 (Metasploitable's MySQL) is **not** in KEV, so it does
not demonstrate the inversion. CVE-2012-1823 (PHP-CGI, on Metasploitable's PHP 5.2.4) **is** in
KEV (EPSS 0.99998, CVSS ~7.5); CVE-2007-2447 (Samba usermap RCE, on its Samba 3.0.20) is **not**
in KEV but is **CVSS 10.0**. The model ranks the KEV PHP CVE above the higher-CVSS non-KEV Samba
CVE — both real on Metasploitable — which is the inversion.
