# ADR-041: Pre-tenant resolution is a closed class of three

**Status:** Accepted
**Date:** 2026-09-03
**Supersedes:** ADR-033

## Context

ADR-033 closed the pre-tenant class at two members and said what to do about a third:

> **Any proposal for a third member.** Adding one is an amendment to this ADR, and the question
> to answer is not "is this lookup safe" but "why does this operation happen before a tenant is
> known, and can that be changed instead".

The operator API needs a third. Every request Core serves must carry a tenant before it reaches
`store`, and a login request carries none: an unauthenticated browser arrives with a hostname, a
form and nothing else. `tenants` is itself tenant-scoped under RLS, so resolving that hostname to
a tenant is the same problem `tenant_for_scan_point` solves for a certificate fingerprint.

**Why it happens before a tenant is known, and whether that can be changed.** It cannot, and the
reason is a rule this codebase already committed to. `internal/control/CLAUDE.md`:

> Login resolves tenant first, by subdomain, SSO issuer, or explicit selection, then the user
> within it. There is no lookup path from a bare email address to an account.

Email is `UNIQUE (tenant_id, lower(email))` — per tenant, not globally — so one address can be a
user of several tenants and there is no email→tenant function to build. Tenant discovery must
ask, not tell. That leaves the hostname, which the client supplies before authentication by
construction. The alternative is not "resolve the tenant later"; it is a global email index,
which is a cross-tenant enumeration oracle sitting in front of an unauthenticated form.

The lookup is therefore genuinely pre-tenant, it has the same shape as the existing two, and
under ADR-033's own reasoning it must join the class rather than become a third one-off.

## Decision

Pre-tenant resolution is a closed class with a fixed shape and **three** members. A fourth
member amends this ADR; it does not simply add a function.

The shape is ADR-033's, unchanged and restated in full rather than cross-referenced, because a
constraint list that lives in a superseded document is one people stop reading.

**The SQL shape.** Every member is a `SECURITY DEFINER` function that is:

- **one input, `RETURNS uuid`** — not a row, not `SETOF`. The caller gets a tenant id and
  nothing else. Widening one into a general cross-tenant read primitive is the failure this
  shape exists to prevent.
- **`STABLE`**, and parameterised — the input is a bind parameter, never interpolated.
- **`SET search_path = pg_catalog, public`** — a `SECURITY DEFINER` function without a pinned
  search path is exploitable by search-path manipulation, and this one runs as the definer.
- **validity-filtered in SQL** — the enrollable-status allowlist for scan points, the
  unredeemed-and-unexpired predicate for tokens, the active-status predicate for domains.
  Filtering in the caller would make the function a broader primitive than the caller needs.
- **`NULL`, never `RAISE`, on no match** — so unknown, expired, revoked and already-used are
  indistinguishable. A distinguishable failure is an oracle for what exists.
- **owned by the migration role, not `cvap_app`**, with **`BYPASSRLS` or `SUPERUSER` on the
  owner asserted at migrate time**. Both are load-bearing: a function `cvap_app` can
  `CREATE OR REPLACE` is a way to run arbitrary SQL as the definer, and every table is
  `FORCE ROW LEVEL SECURITY`, so `SECURITY DEFINER` alone cannot read one.

**The Go shape.** One exported method per member on `*store.DB`, returning **exactly
`(TenantID, error)`** and nothing wider — never a connection, because the store's whole design
is that no code path obtains one without a tenant. All members share one unexported
implementation, `resolvePreTenant`, which is the only place in the package that queries the raw
pool. One sentinel, `ErrTenantNotResolved`, for every resolution failure; a genuine database
fault is wrapped separately, so a broken function does not hide behind a message that reads like
an ordinary unknown input.

**The members, and nothing else:**

| Function | Input | Used by |
|---|---|---|
| `tenant_for_scan_point(text)` | certificate fingerprint | `RotateCertificate`, dispatch, ingest |
| `tenant_for_enrollment_token(bytea)` | SHA-256 of the token | `Enroll` |
| `tenant_for_domain(text)` | request host, lowercased, port stripped | API tenant resolution, before any handler |

`encapsulation_test.go` checks the class rather than one function name.

**The third member's validity filter is the tenant's own status**, so a suspended or deleted
tenant resolves to `NULL` and its users cannot log in — the same NULL an unknown hostname
produces, which is what keeps the endpoint from confirming that a tenant exists.

**Every deployment sets a domain, including on-prem, including `localhost`.** A single-tenant
deployment that skipped resolution and assumed "the only tenant" is the exact branch ADR-017
exists to prevent: a second code path where tenancy is implicit, which is correct until the day
a second tenant appears and is then wrong everywhere at once. `localhost` is a domain. Setting
it costs one row.

## Alternatives considered

**A second bespoke function, reasoned about on its own.** ADR-033 rejected this for the second
member and the argument is unchanged for the third: the members would drift in whether the
validity filter lives in SQL or the caller, and whether no-match raises or returns NULL. Both
differences are oracles, and neither looks like one in a diff.

**Resolve the tenant from a request field — a form input, a header, a JSON body key.** Simplest
possible thing, and it is what the login form appears to want. Rejected: a tenant identifier the
client can set is a tenant identifier an attacker can set, and it would sit in front of the one
endpoint that runs before authentication. The host is also client-supplied, but it is bounded by
what the deployment's DNS and TLS actually terminate, and it is the value the operator
configured rather than a value the request invented.

**Look the user up by email across tenants and infer the tenant from the match.** No hostname
needed, and it is what every consumer product does. Rejected on an existing decision, not a new
one: `internal/control/CLAUDE.md` forbids it, email is unique per tenant rather than globally,
and the endpoint would answer "does this address have an account anywhere in this deployment"
to anyone who asks.

**Make `tenants` global — no RLS on that one table — so the lookup is an ordinary query.**
Tempting because a tenant row is not really another tenant's data. Rejected for ADR-033's
reason: `tenants` carries name, status and configuration, and RLS exists to contain *our* bugs.
An unauthenticated handler that can select from `tenants` at will can enumerate every customer
of the deployment, which is precisely the read the narrow function refuses to be.

**Skip resolution when the deployment has exactly one tenant.** The on-prem convenience.
Rejected above and worth restating as an alternative because it will be proposed again: it
creates a second tenancy path that is exercised only in the deployments least likely to be
tested against multi-tenancy, and it fails open — a deployment that grows a second tenant
silently keeps using the path that ignores which one is asking.

## Consequences

Three exceptions to ADR-002 exist, all narrow, all identical in shape, all auditable by reading
one page. The class grew by one and its shape did not move, which is the outcome ADR-033's
review trigger was designed to produce.

Tenant resolution now runs on **every** API request, not only at login, because a session cookie
is scoped to the tenant that issued it and the middleware must know which tenant is being asked
about before it can validate one. That makes `tenant_for_domain` the hottest of the three
members by a wide margin; it is `STABLE` and indexed on a unique lowercased domain, and it
returns one uuid.

A deployment reached by an unconfigured hostname gets a clean failure at the middleware and no
handler runs. That is a deployment error rather than an attack, and it presents identically to
an attack, which is the intended behaviour and the reason the failure carries no detail.

The cost ADR-033 named is unchanged and now applies three times: the migration-time assertions
are copied rather than shared, because a shared helper would itself need to be `SECURITY
DEFINER`.

## Review trigger

**Any proposal for a fourth member**, on the same terms: not "is this lookup safe" but "why does
this operation happen before a tenant is known, and can that be changed instead". Also revisit if
a member ever needs to return more than a tenant id — the change that would turn one into a
cross-tenant read primitive — or if a deployment needs several hostnames for one tenant, which is
a `tenant_domains` table rather than a wider function.
