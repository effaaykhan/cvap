# ADR-052: A CSV export refuses over its cap rather than truncating, and export is its own permission

**Status:** Accepted
**Date:** 2026-09-05

## Context

Session 18 added CSV export for findings and assets (execution-plan §2's "CSV export only").
An export is the read most likely to be pointed at a whole tenant's estate, and it raised two
questions the read endpoints did not: what happens when the result is larger than we are
willing to stream, and whether pulling the whole set into a file is the same authority as
reading a page of it.

## Decision

### An over-cap export is refused, not truncated

Each export is bounded by a row cap (`store.ExportRowCap` / `AssetExportRowCap`, 50k,
configurable). An export whose result would exceed the cap is **refused** with `422` and a
fixed sentence telling the caller to narrow it with a filter. It is never truncated to the cap.

**A truncation header alone is insufficient, and this is the reasoning to keep** — because the
obvious cheaper design is to return the first N rows plus `X-CVAP-Truncated: true`, and the
next person adding an export endpoint will reach for exactly that.

The header can be *set*. It cannot be *acted on*. A CSV export has no cursor and no ordering
guarantee a client may resume from: the rows are a one-shot dump, not a page of a keyset walk.
So "truncated: true" tells the reader their file is incomplete and gives them **no way to
obtain the rest** — there is no "next page" to request, because there is no stable position to
request it from. A flag whose only honest responses are "ignore it" or "give up" is worse than
no flag, because the first response is the one that happens: a spreadsheet user opens a file
that looks complete, and the header is in an HTTP response they never saw. The refusal is the
honest alternative precisely because it hands back a **fixable** instruction (narrow the
filter) rather than an unfixable state (a short file and a flag pointing at nothing).

The cap is enforced as a `LIMIT cap+1` in the store query, so the refusal decision is
memory-bounded — the export never loads the whole tenant to discover it is too big — and both
export handlers route the check through one `overExportCap` so the decision lives in one place.

### Export is a permission of its own

Export is gated by `finding.export_all` and `asset.export_all`, held by **operator and above**,
not by every reader (`finding.read` / `asset.read`). Reading a finding is triage; pulling the
whole tenant's findings or assets into a single file is exfiltration shaped like a feature. The
row that leaves in a CSV is the same row a reader sees, but one is a page and the other is the
estate, and a deployment should be able to let an analyst read without letting them walk out
with everything at once. The `_all` in the name says what is authorised: the whole set, bounded
only by the cap. There is no production role provisioning yet, so like every permission these
are granted only in test fixtures today; the intent recorded here — operator and above — is what
that provisioning will implement.

## Alternatives considered

**Truncate and set a header.** Cheapest, and it is what most exports do. Rejected on the
reasoning above: a truncation flag on a cursor-less, unordered dump names an incompleteness the
client cannot resolve, so it is ignored and the short file passes for complete.

**Page the export.** The genuinely correct answer to "the result is too big": stream it in
pages the client reassembles. Deferred, and the unblocker is not "implement paging" — it is
**whether a stable sort key exists at all.** Keyset paging needs an ordering that does not move
under a client walking it. The natural keys here — `(last_seen, finding_id)` for findings,
`(last_seen, asset_id)` for assets — are **not** stable: `last_seen` advances every time a scan
re-observes the row, which reorders it mid-walk, so a paging client would skip and repeat rows
on a live-updating table. A stable export therefore needs one of: a point-in-time snapshot
read, or a sort key that never moves (`first_seen` + id, or a dedicated immutable sequence).
Deciding which is the open question this defers; "add paging" without answering it would ship
the skip-and-repeat bug. State it as the sort-key question, not the paging feature.

**Reuse the read permission for export.** One fewer permission. Rejected: it makes bulk
exfiltration a property of being able to read, which is the line operator-and-above exists to
draw.

**No cap at all.** Rejected: an unbounded export is a memory and time cost any authenticated
caller can trigger against the largest table in the tenant.

## Consequences

Both export routes refuse over the cap with a fixable message, and neither can produce a file
that is silently short of the truth. Two new permissions enter the closed set. The next export
endpoint inherits `overExportCap` and the reasoning above, so it does not re-derive the
header-is-insufficient argument or reach for a truncation flag.

A legitimate export larger than the cap is refused today, which is a real limit an operator
hits by having a large estate and no filter that narrows it enough. That is the trigger below,
and the answer to it is the stable-sort-key decision, not a bigger cap — a bigger cap moves the
wall without removing it.

The formula-injection neutralisation (`csvSafe`) is part of the same handler: a derived field
like a hostname is attacker-influenceable, and a value beginning `=`, `+`, `-`, `@`, tab or CR
is a formula a spreadsheet runs on open, so it is prefixed to force text. Recorded here so the
next export endpoint applies it too.

## Review trigger

A design partner whose legitimate, well-filtered export still exceeds the cap. That is the
point at which paging earns its keep, and the first thing it forces is the choice between a
snapshot read and an immutable sort key — because the live `last_seen` key the list paginates
on cannot carry an export.
