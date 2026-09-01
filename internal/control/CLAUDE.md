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

**Login resolves tenant first**, by subdomain, SSO issuer, or explicit selection, then the
user within it. There is no lookup path from a bare email address to an account.

The consequence, which is real and must be designed for rather than worked around: tenant
discovery is its own problem. A user at two tenants who types only an email cannot be
routed automatically. Any "which tenant?" flow that answers from the email address is the
enumeration oracle the per-tenant constraint exists to avoid — **it must ask, not tell.**

Run `security-reviewer` on any change to auth, tenancy or the API surface.
