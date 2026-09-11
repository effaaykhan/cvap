# Enterprise console — design spec (backlog #12)

**Date:** 2026-09-09
**Status:** Design — approved direction (IA + visual language), spec for review before an implementation plan.
**Canvas (visual language + screen mockups):** https://claude.ai/code/artifact/5506854c-58fc-4758-9798-6f25d48d93c2

The current operator UI is one screen per table — a developer's view of the data model. This rebuild
makes it a security triage console. Per ADR-059 it was held until P3.4 so the data carries real
priority and confidence distinctions; those now exist (findings carry KEV/EPSS/priority/confidence,
`advisory_status`, coverage state), so the triage view can be designed once, against real signal.

This session's output is **the design**, not the build (chosen deliverable). No UI code lands here;
the implementation follows as its own planned effort.

## Goals — the five rungs, in order

The ordering is the point; each rung stands on the one above, and rung 1 outranks all.

1. **Accurate first.** Every number reproducible from the finding set; nothing overstates weak data.
   The S23 honest-weak-data floor (exposure caveat, low-confidence OS, softmatch "unknown") is the
   floor, not the ceiling — no visual polish may erode it. This is the hard constraint the visual
   design serves, never fights.
2. **An operator landing view** answering *what changed since I last looked / what is worst right now
   / what is not working* — not a list of tables.
3. **Findings triage as the centre of gravity.** Severity and confidence together, filterable,
   evidence one click away. An advisory-matched claim and a banner-inferred one are *different
   claims*; the confidence axis is an **open spectrum** so P3.5's NVD-CPE low-confidence tier slots
   into the existing lane without a redesign.
4. **Fleet and scan health without hunting:** scan points offline, scans blocked for capacity (the
   silent-success class, #3), kill-switch state (#8), ingest backlog.
5. **Trend over time** — a count with no history says nothing about whether you are winning.

## Information architecture (approach A — approved)

Landing-first, triage-centric; **reuse the existing honest detail views** (finding/asset/scan detail
already satisfy rung 1). Rebuild the shell and the list/landing/health surfaces, not the details.

- **Overview** (landing, rung 2) is home — replaces the table-list nav as the first screen.
- **Triage** (rung 3) is the primary working surface.
- **Health** (rung 4) is a dedicated fleet/scan surface fed by new reads.
- **Assets / Knowledge** remain, restyled to the new vocabulary; **detail views are reused as-is**.
- Trend (rung 5) appears as a strip on Overview and Triage, backed by a history read.

Nav: `Overview · Triage · Assets · Health · Knowledge`. The retrospective-sweep surfaces
(#3/#5/#6/#7/#8) are *consumed* here (rungs 1 and 4), not patched onto old screens.

## Visual design language

Extends the shipped token system (`internal/control/api/web/src/styles.css`), it does not replace it.
Dark-default; the light theme keeps its token swaps. The console is dense, calm, and data-first.

- **Palette:** the existing tokens verbatim — `--bg #0d1117`, surfaces, `--fg`/`--muted`/`--faint`,
  one `--accent`, `--ok`/`--danger`. Severity is its own scale (`--sev-*`), never the accent, each
  value ≥4.5:1 on `--surface`.
- **Type:** system sans at 13px/1.5; `h1` 1.15–1.25rem/650; section labels .68rem/700 uppercase
  muted; **mono for every datum** (ids, CVEs, ports, versions, scores).
- **The finding row is the signature:** a left rail whose weight (2–4px) and colour track rank, the
  severity *word* carrying it for anyone who cannot see hue, colour only reinforcing.
- **Priority primitives:** the `KEV` badge (filled danger chip, the loudest thing on a row;
  ransomware-linked outlined); EPSS/CVSS as mono values with a dash for unscored (never 0);
  `priority_basis` as a quiet mono label.
- **Confidence spectrum** (rung 3): one lane, `advisory-matched → banner-inferred → CPE (P3.5) →
  unscored`, each a fixed dot colour; the lane is open at the low end so P3.5 adds a stop, not a
  redesign.
- **Honest states as chips:** `clean / cannot-know / vulnerable / no-release` (advisory_status), feed
  freshness `current / stale / never`, exposure labelled *zone-derived (external/dmz)* — a coarse
  classification, never presented as a per-asset reachability probe.
- **No AI-slop:** no gradient hero, no emoji in content, no rounded-corner-left-accent cards; inline
  stroke SVG icons on a 16/20/24 grid.

The four artboards on the canvas are: **Design language** (the tokens + primitives above), **Overview**,
**Triage**, **Fleet & scan health**.

## Per-rung design

**Rung 2 — Overview.** A metric strip (KEV-on-fleet, open findings, assets assessed, "not working"
count) with deltas since last visit; then three regions: *Worst right now* (top of the priority list,
KEV first, with the inversion visible), *Changed since your last visit* (new/reopened findings, new
KEV listings that re-ranked, newly-out-of-coverage releases, remediations), *Not working* (scan point
down, scans blocked, stale feed, ingest backlog, kill-switch state). A 30-day trend line for open
findings with a KEV sub-line.

**Rung 3 — Triage.** Filter bar (status, KEV-only, severity band, confidence lane, asset/CVE search).
A priority-ordered table: `priority (rank + KEV + basis) · severity (rail+word) · finding (CVE +
rule) · asset · confidence (lane + label) · EPSS · CVSS · exposure (zone-derived) · evidence ›`. A row
expands to the evidence an analyst confirms by hand (advisory, installed→fixed, comparator,
confidence breakdown) — evidence one click away, no re-scan. The confidence-spectrum legend sits under
the table. The KEV-over-higher-CVSS inversion (CVE-2012-1823 above CVE-2007-2447) is the worked
example.

**Rung 4 — Health.** Scan points worst-first (offline/degraded/online, last-seen, zones with no scan
point); scans running/blocked-for-capacity (the #3 silent-success class, named not hidden); knowledge
feeds with freshness chips (USN/KEV/EPSS/coverage and their thresholds); pipeline & safety (ingest
backlog, unresolved correlations, kill-switch armed/inactive, scope-enforcement sites). Every state
is server-owned, not client-inferred.

**Rung 5 — Trend.** Open-finding and KEV-on-fleet counts over time, on Overview and Triage.

## Backend reads — the engineering output (exist vs. build)

| Surface | Read | Status |
|---|---|---|
| Triage list, detail, exposure | `GET /v1/findings`, `/v1/findings/{id}`, `/v1/exposure` | **exist** (priority-ordered; KEV/EPSS/CVSS/confidence/`priority_basis`; advisory_status) |
| Assets, knowledge freshness | `GET /v1/assets`, `/v1/assets/{id}`, `/v1/knowledge/freshness` | **exist** |
| Scan points | `GET /v1/scan-points` | **exists** (worst-first); confirm it carries offline/last-seen |
| Overview "worst now" | top-N of `/v1/findings` | **exists** (reuse) |
| Overview "what changed" | findings/KEV/coverage delta since a timestamp | **build** — a summary/delta read |
| Overview + Health "not working" | scans blocked for capacity (#3), kill-switch state (#8), ingest backlog | **build** — no read today (`Observations.PendingOlderThan` is a metric, not an endpoint) |
| Trend (rung 5) | finding counts over time from `finding_history` | **build** — a history/rollup read |

Rungs 1 and 3 are servable on existing reads; rungs 2, 4, 5 need new read endpoints. That split
phases the implementation: **triage + the design language first (no backend work), then the landing
and health reads, then trends.** Each new read follows the route-registry contract (ADR-043) and is
tenant-scoped through `Read`; none needs a schema change except possibly a lightweight
finding-count-history rollup for rung 5 (to be decided in the plan — `finding_history` may suffice).

## Non-goals

- Not rebuilding the detail views (they satisfy rung 1).
- Not a visual-polish-over-accuracy pass — rung 1 forbids it.
- Not pulling Phase 4 (credentialed) forward — the sequencing decision is separate and open.
- Not the `internet_reachable`/exposure work — resolved in ADR-074 (this spec consumes the derived,
  labelled exposure signal).

## Open questions for review

1. **Rung 5 storage:** is `finding_history` enough for a trend line, or is a daily count rollup
   warranted? (Decide in the plan; leaning: derive from `finding_history` first, add a rollup only if
   the query is too heavy at scale.)
2. **"What changed" baseline:** per-user last-visit timestamp (needs storing) vs. a fixed window
   (e.g. 7 days). Leaning: a fixed window first (no new per-user state), last-visit later.
3. **Phasing:** confirm the three-phase split above (triage+language → landing+health → trends) for
   the implementation plan.

## Implementation status (S42, 2026-09-11)

Built, on the reads the console needs, in `internal/control/api/web` (`Overview.tsx`,
`Findings.tsx` as Triage, `Health.tsx`, `components/Trend.tsx`, the console section of
`styles.css`, `lib/console.ts` for every rule about what a number means, unit-tested). Nav is
`Overview · Triage · Assets · Health · Knowledge`; the old paths redirect; the detail views are
reused as-is, as the IA says.

The two reads the backend table marked **build** now exist, registered through the route registry
(ADR-043) and typed into the client by `make ui-types`:

- `GET /v1/findings/summary` (finding.read): exact open and KEV counts, counts by severity, what
  changed inside a fixed window (`days`, default 7: new, resolved, reopened from `finding_history`,
  newly KEV-listed, with the worst named), and a daily open/KEV series (`trend_days`, default 30)
  derived from `first_seen` and `resolved_at`. This settles open questions 1 and 2: the trend is
  derived from the finding rows, no rollup; the window is fixed, not a per-user last visit.
- `GET /v1/health` (scan.read): scans blocked for capacity (the same `CountDispatchable` predicate
  scan creation refuses on, asked again after the fleet changed), ingest backlog and unresolved
  observations over the last 7 days, unresolved kill switches with their unacknowledged scan
  points, credential grants past expiry with no attestation.

Every region of the four artboards is live: Overview's metric strip with deltas, worst-right-now
with the KEV inversion explained only when visible, changed-in-window, not-working (kill switch,
blocked scans, backlog, unconfirmed grants, scan points, feeds, failed scans), and the 30-day
trend with hover and a table view; Triage complete; Health with blocked scans and the
pipeline-and-safety card on real counters. The tests move a finding through open, resolved and
reopened and require the counts and the series to follow, and put a scan point offline to make a
scan read as blocked (`overview_read_test.go`).
