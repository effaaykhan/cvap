# ADR-068: The advisory assessment state is a server-owned enum on the asset

**Status:** Accepted
**Date:** 2026-09-09

Extends ADR-067 (the coverage window and cannot-know) to the wire. ADR-067 made matching return
three states — `vulnerable` / `clean` / `cannot_know` — in the store. This states how they reach
a client, because the defect ADR-067 fixes (cannot-know collapsing into clean) collapses again if
the API lets an empty finding list mean both.

## Context

The finding-list endpoint (`GET /v1/findings?asset_id=X`) returns an empty array for a host with
no findings — whether that host is genuinely clean (release in advisory coverage, nothing matched)
or cannot-know (release past its coverage window). If the three-state distinction lives only in the
store, a client renders both the same way: "no findings", read as clean. The harm ADR-067 names —
an operator acting on "clean" that means "unknown" — is reintroduced at the wire.

A field a client *may* read is not enough; the requirement is that a client which **ignores** the
state cannot render "clean" by accident.

## Decision

**Advisory-clean is expressible only as one value of a server-owned enum, never as the emptiness
of a list.**

### 1. `advisory_status` is a first-class enum on the asset

The asset (both `AssetSummary` in listings and `AssetResponse` in detail) carries
`advisory_status`, computed server-side by `domain.AssetAdvisoryStatus`:

- `no_release` — no distro release resolved (family-only or no attribution); advisory matching did
  not run. Not a clean result and not a coverage result — matching never happened.
- `cannot_know` — release resolved but past its coverage window (or window unknown); a no-match is
  the absence of evidence (ADR-067).
- `clean` — release resolved **and** in coverage, and no advisory finding. The only value that
  asserts advisory safety, and the server emits it only when coverage is `covered`.
- `vulnerable` — an advisory matched. (Dormant until P3.4 produces advisory findings; defined now so
  the enum is total and the client's switch is complete from the start.)

### 2. Emptiness is never the clean signal

The findings array is rule-based findings (ADR-013/050); it does not represent advisory matching,
and advisory findings (P3.4) will be entries *in* it, never its absence. So "advisory clean" is not
derivable from an empty findings array — there is no `findings.length === 0 → clean` path, because
the findings list never expressed the advisory verdict in the first place. The verdict is
`advisory_status`, and nothing else carries it.

When P3.4 lands advisory findings, a `vulnerable` host has them in the list; the `clean` vs
`cannot_know` distinction — both have no advisory finding — remains expressible **only** through
`advisory_status`. That is the invariant this ADR fixes in place before the finding pipeline that
would otherwise blur it exists.

### 3. The asset-scoped finding list carries it too

`GET /v1/findings?asset_id=X` returns, alongside the (possibly empty) findings, that asset's
`advisory_status`. A client reading only the finding endpoint still receives the verdict, so it need
not cross-reference the asset endpoint to avoid the collapse.

### Why this is structural, not documentary

A client that ignores `advisory_status` has **no** advisory verdict to render — not a wrong one.
There is no boolean `clean`, no "0 findings" that means advisory-clean, nowhere emptiness is a
verdict. The clean/cannot-know decision is made once, server-side, gated on coverage, and shipped
as a single value. Losing it requires inventing a verdict the API never sent, rather than
mishandling one it did.

## Consequences

- The UI renders `advisory_status` as the host's advisory posture: `clean` → "no known advisory
  vulnerabilities (release in coverage)"; `cannot_know` → "not assessable — release out of advisory
  coverage"; `no_release` → "release unresolved — unmatched for advisories"; `vulnerable` → the
  matched findings. The word "clean" is reachable in the UI only from `advisory_status === "clean"`.
- `AssetAdvisoryStatus` is pure and total (`internal/domain/coverage.go`), tested so each input
  combination maps to exactly one state and `clean` requires both a resolved release and coverage.
- Today, with no advisory findings, an asset is `no_release`, `clean`, or `cannot_know`; `vulnerable`
  activates with P3.4 at no change to this contract.
