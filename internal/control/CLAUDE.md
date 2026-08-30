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

Run `security-reviewer` on any change to auth, tenancy or the API surface.
