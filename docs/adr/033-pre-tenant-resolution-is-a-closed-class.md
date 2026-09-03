# ADR-033: Pre-tenant resolution is a closed class

**Status:** Superseded by ADR-041
**Date:** 2026-09-01

## Context

ADR-002 makes every read tenant-scoped. ADR-031 carved out one exception, because scan point
enrolment cannot satisfy that rule: a scan point presents a client certificate and nothing
else, so Core must derive the tenant *before* it can set `app.tenant_id`, and `scan_points` is
tenant-scoped. Its review trigger said what to do if it happened again:

> Also revisit if a second enrolment-time lookup appears needing the same treatment — two
> exceptions is a pattern, and a pattern deserves a mechanism rather than a second bespoke
> function.

It has happened. Enrollment tokens carry the tenant and the zone, and `enrollment_tokens` is
tenant-scoped for the same reason everything else is — so resolving a token to its tenant has
exactly the same shape as resolving a fingerprint. Written as a second one-off, the two would
drift: one would gain a status filter the other lacked, or start raising where the other
returned NULL, and the difference would be an oracle nobody chose.

## Decision

Pre-tenant resolution is a **closed class** with a fixed shape and two members. A third member
amends this ADR; it does not simply add a function.

**The SQL shape.** Every member is a `SECURITY DEFINER` function that is:

- **one input, `RETURNS uuid`** — not a row, not `SETOF`. The caller gets a tenant id and
  nothing else. Widening one into a general cross-tenant read primitive is the failure this
  shape exists to prevent.
- **`STABLE`**, and parameterised — the input is a bind parameter, never interpolated.
- **`SET search_path = pg_catalog, public`** — a `SECURITY DEFINER` function without a pinned
  search path is exploitable by search-path manipulation, and this one runs as the definer.
- **validity-filtered in SQL** — the enrollable-status allowlist for scan points, the
  unredeemed-and-unexpired predicate for tokens. Filtering in the caller would make the
  function a broader primitive than the caller needs.
- **`NULL`, never `RAISE`, on no match** — so unknown, expired, revoked and already-used are
  indistinguishable. A distinguishable failure is an oracle for what exists.
- **owned by the migration role, not `cvap_app`**, with **`BYPASSRLS` or `SUPERUSER` on the
  owner asserted at migrate time**. Both are load-bearing: a function `cvap_app` can
  `CREATE OR REPLACE` is a way to run arbitrary SQL as the definer, and every table is
  `FORCE ROW LEVEL SECURITY`, so `SECURITY DEFINER` alone cannot read one.

**The Go shape.** One exported method per member on `*store.DB`, returning **exactly
`(TenantID, error)`** and nothing wider — never a connection, because the store's whole design
is that no code path obtains one without a tenant. All members share one unexported
implementation, `resolvePreTenant`, which is the only place in the package that queries the
raw pool. One sentinel, `ErrTenantNotResolved`, for every resolution failure; a genuine
database fault is wrapped separately, so a broken function does not hide behind a message that
reads like an ordinary unknown input.

**The members, and nothing else:**

| Function | Input | Used by |
|---|---|---|
| `tenant_for_scan_point(text)` | certificate fingerprint | `RotateCertificate`, and dispatch/ingest in session 8 |
| `tenant_for_enrollment_token(bytea)` | SHA-256 of the token | `Enroll` |

`encapsulation_test.go` checks the class rather than one function name.

## Alternatives considered

**A second bespoke function, reasoned about on its own.** What ADR-031's review trigger
anticipated and rejected in advance. The two would drift in exactly the ways that matter:
whether the validity filter lives in SQL or the caller, whether no-match raises or returns
NULL. Both differences are oracles, and neither would look like one in a diff.

**Make the tables global, with no `tenant_id` and no RLS, like the knowledge tables.** Then no
exception is needed at all — the lookups become ordinary queries. Rejected: `rule_packs` and
`vulnerability_defs` are global because they are genuinely the same for every tenant.
`enrollment_tokens` and `scan_points` are per-tenant data, and RLS exists to contain *our*
bugs (ADR-002). Removing a table's isolation to dodge a lookup problem is the erosion that
argument warns about, and it would let a defect in the enrollment handler enumerate every
tenant's pending enrollments.

**One generic `tenant_for(kind text, key text)` function.** Fewer objects, and superficially
"the mechanism" the review trigger asked for. Rejected: it takes a caller-chosen discriminator,
so its blast radius is the union of every lookup anyone ever adds, and a bug in the dispatch
inside it is a bug in all of them. A closed class of narrow functions is a mechanism; a wide
function with a switch is the opposite.

**Resolve the tenant from the certificate itself, by putting `tenant_id` in a SAN.** No
database lookup at all. Rejected: a certificate cannot express revocation, so this would
require a CRL or OCSP to answer a question the database already answers immediately, and the
status filter — a revoked scan point must not resolve — would have nowhere to live.

## Consequences

Two exceptions to ADR-002 exist, both narrow, both identical in shape, both auditable by
reading one page. `security-reviewer` has a class to check rather than a growing list of
one-offs, and the next person who needs one finds the shape already decided.

The cost is a small amount of ceremony for what could each be three lines of SQL, and a rule
that will feel disproportionate to whoever needs the third member. That is the point: the
friction is where the review happens. It also means the class has a maintenance obligation —
the assertions in each migration are copied rather than shared, because a shared helper
function would itself need to be `SECURITY DEFINER`.

## Review trigger

**Any proposal for a third member.** Adding one is an amendment to this ADR, and the question
to answer is not "is this lookup safe" but "why does this operation happen before a tenant is
known, and can that be changed instead". Also revisit if a member ever needs to return more
than a tenant id, which is the change that would turn one into a cross-tenant read primitive.
