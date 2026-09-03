# internal/control

Control Plane services: auth and RBAC, tenancy, asset management, scan orchestration,
policy, finding pipeline, risk. **Decides, never scans.** Nothing in this package opens a
connection to a target.

Rules:

- Never imports `internal/scanpoint` or `internal/engines`. Dependencies point inward:
  control depends on `domain` and `store`, not the reverse.
- Assets and findings are **derived here** from observations, never written by a scan point
  (ADR-006). If a code path lets scan point input reach the asset or finding tables without
  passing through derivation, that is the bug.
- Every request carries a tenant context before it reaches `store`. RLS is the backstop,
  not the plan (ADR-002).
- Scope enforcement at planning time is one of the two enforcement sites (ADR-024). The
  other is the scan point runtime. There is no third.
- Findings carry a `rule_id` always and a `vuln_def_id` optionally. Nothing may branch on
  `vuln_def_id` being present (ADR-009).
- Exposure is computed per vantage point, never read from a column on the asset (ADR-008).

## Email is not a global key

`users` is constrained `UNIQUE (tenant_id, lower(email))` — per tenant, as a functional
index, not a plain column constraint. Two reasons, and both look like obstacles if you meet
the constraint before the reasoning:

- One person may hold accounts at two tenants. A global unique email forecloses that, and
  retrofitting it later means touching every account.
- A global constraint is a membership oracle: signup tells an anonymous caller whether an
  address already exists somewhere in the platform.

Email is stored **as entered** and compared lowercased. Do not normalise on write — it
loses what the user typed, and that shows up in outbound mail.

**Login resolves tenant first**, then the user within it. There is no lookup path from a bare
email address to an account.

It resolves it from the **request host**, and from nothing else (ADR-041). This sentence used
to offer "subdomain, SSO issuer, or explicit selection" as three options; two of them do not
exist, and the SSO issuer one is forbidden by ADR-046 — the callback must be unable to name its
own tenant, which is precisely what choosing a tenant by issuer would be.

The consequence, which is real and must be designed for rather than worked around: tenant
discovery is its own problem. A user at two tenants who types only an email cannot be
routed automatically. Any "which tenant?" flow that answers from the email address is the
enumeration oracle the per-tenant constraint exists to avoid — **it must ask, not tell.**

The answer, since ADR-041: **the request HOST names the tenant.** `tenants.domain` is
globally unique and `tenant_for_domain()` resolves it before any handler runs, which is the
third member of the pre-tenant class. `Tenants.Create` requires a domain and has no overload
that omits one — on-prem included, where it is usually `localhost`. A single-tenant path that
skipped resolution is the branch ADR-017 exists to prevent.

## internal/control/api

Design below; **how it is tested is in `internal/control/api/CLAUDE.md`**, and that file is not
optional reading — a cookieless test suite made login CSRF structurally invisible here.

The operator API. One package, and the shape of it is ADR-043's: **each endpoint is declared
once as a `Route` value**, which is simultaneously what the mux dispatches on, what the
middleware enforces, and what the OpenAPI document is emitted from. They cannot disagree
because there is only one of them. Do not replace this with annotations — a comment cannot
prevent a route whose declared permission and enforced permission differ, because nothing reads
a comment at runtime.

- **`Access` has no default.** `AccessUndeclared` is the zero value and always a registration
  error, so a route added without deciding who may reach it stops the process at startup.
  `Server.mount` builds the chain per route from that route's own declaration and the handler is
  referenced nowhere else, so there is no path to a handler that skips its own middleware.
- **The tenant is read in exactly one place**, from `r.Host`, by `resolveTenant`. No handler,
  body, header or claim may supply one, and `DisallowUnknownFields` turns a body carrying
  `tenant_id` into a 400 rather than silently ignoring it.
- **Permissions are a permission list**, so empty denies (ADR-037) — the `roles.permissions`
  default `'{}'` grants nothing. No wildcard, no hierarchy: `scan.cancel` does not follow from
  `scan.create`, and `scan.safety_mode` is separate from both because ADR-021's escalation is a
  decision somebody is authorised to take rather than a property of a plan.
- **Store errors never reach a client.** `mapError` embeds constraint and column names;
  `errors.go` maps a sentinel to a status and a fixed sentence and logs the rest against the
  request id.
- **Local password auth is gated by three conditions**, all required: the Core-wide
  `CVAP_CORE_LOCAL_AUTH` flag, `tenants.deployment_mode = 'onprem'`, and
  `tenant_auth_config.method = 'local'`. The flag is Core-wide rather than per tenant so that a
  tenant admin cannot enable password login for their own users and thereby opt out of the
  deployment operator's SSO policy.
- **Login has one refusal for every failure.** Wrong password, unknown address, an address
  belonging to another tenant, a suspended tenant, the flag being off: one status, one body.
- **Single sign-on (ADR-046, superseding ADR-045).** Authorization code with PKCE, no client secret anywhere.
  A returning user is identified by `users.oidc_subject`, never by email — email links an
  invited account to a subject ONCE, only with `email_verified`, and only while
  `oidc_subject IS NULL`. Both halves of the flow run behind `resolveTenant`, so the callback
  can name no tenant: the state is redeemed inside the tenant its HOST resolved to, and `iss`,
  `aud` and `nonce` are checked against that tenant's row and that attempt.
- **The OIDC issuer is the only URL Core fetches that an operator supplied**, so the SSRF guard
  is at dial time on the resolved address, is an allowlist of public unicast, and refuses
  link-local even when `CVAP_CORE_OIDC_ALLOW_PRIVATE_ISSUER` permits the internal network —
  an on-prem operator needs `10.0.0.5` and nobody needs `169.254.169.254`.

Run `security-reviewer` on any change to auth, tenancy or the API surface.
