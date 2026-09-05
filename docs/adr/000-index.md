# Architecture Decision Records

Decisions are recorded so a change can be checked against them, and so a future reader
knows what was rejected. Accepted ADRs are superseded, never edited — the
`protect-contracts` hook enforces this.

Create one with `/new-adr <title>`. Check a change against them with the
`adr-compliance` subagent.

| # | Decision | Status |
|---|---|---|
| 001 | Go for core, scan points and agents; Python for knowledge pipelines | Accepted |
| 002 | PostgreSQL as system of record; RLS enforces tenancy | Accepted |
| 003 | Job dispatch via Postgres SKIP LOCKED; broker deferred | Accepted |
| 004 | Broker never exposed; dispatch service fronts it | Accepted |
| 005 | Scan point transport posture: outbound-only, scan-point-initiated mTLS | Accepted |
| 006 | Observation-first — scan points never write assets or findings | Accepted |
| 007 | Asset identity by ranked keys with retained merge evidence | Accepted |
| 008 | Zone is a property of observations; exposure is derived | Accepted |
| 009 | Rule / VulnerabilityDef / VendorAdvisory are separate entities | Accepted |
| 010 | Finding dedup keys are source-specific; SAST keys on symbol not line | Accepted |
| 011 | Scan / Job / Task three-level decomposition | Accepted |
| 012 | Job leases carry monotonic fencing epochs; reassign_safe gates retry | Accepted |
| 013 | Detection split — request-coupled at scan point, evidence-based at core | Accepted |
| 014 | Vendor advisories are authority for packages; CPE is flagged fallback | Accepted |
| 015 | Large evidence to object store; summary in Postgres | Accepted |
| 016 | Observations partitioned monthly, 90-day default retention | Accepted |
| 017 | Tenant-aware always, single-tenant by configuration | Accepted |
| 018 | PKI trust anchor is configuration, not assumption | Accepted |
| 019 | Knowledge data is signed; offline import supported | Accepted |
| 020 | Credentials just-in-time, scoped, memory-only on scan points | Accepted |
| 021 | Safe mode default; detection without impact | Accepted |
| 022 | Protocol versioning is additive-only within a major version | Accepted |
| 023 | Compose first; Kubernetes deferred | Accepted |
| 024 | Scan blast-radius controls | Accepted |
| 025 | Build-versus-consume boundary | Accepted |
| 026 | Result submission contract | Accepted |
| 027 | Engines are separate processes behind a job contract | Accepted |
| 028 | One pre-release correction to the frozen wire contract | Accepted |
| 029 | Schema tables the v2 ERD does not draw | Accepted |
| 030 | Knowledge tables are read-only to the application role | Accepted |
| 031 | Enrolment tenant lookup is a one-value SECURITY DEFINER function | Accepted |
| 032 | The store package exposes no path to a raw connection | Accepted |
| 033 | Pre-tenant resolution is a closed class | Superseded by ADR-041 |
| 034 | No interceptor, middleware or tracing layer may render message bodies | Accepted |
| 035 | A hand-written type holding a secret stores it in a func() string | Superseded by ADR-038 |
| 036 | The sweep enumerates tenants, and that is the only unscoped read | Accepted |
| 037 | Empty means deny for permission lists, unrestricted for constraint lists | Accepted |
| 038 | A secret field is a func of a type that can be zeroised | Accepted |
| 039 | Translated address forms expand exclusions and do not expand allows | Accepted |
| 040 | A target that names an address must parse as one, or the job is refused | Accepted; consequences amended by ADR-044 |
| 041 | Pre-tenant resolution is a closed class of three (supersedes 033) | Accepted |
| 042 | Targets are canonicalised once at planning, and re-canonicalised at the scan point | Superseded by ADR-044 |
| 043 | The route registry is the API contract, and the OpenAPI document is emitted from it | Accepted |
| 044 | Target canonicalisation, restated with three claims corrected (supersedes 042) | Accepted |
| 045 | OIDC identity is the subject, the client is public, and the issuer is a network the deployment trusts | Superseded by ADR-046 |
| 046 | OIDC, restated with the SSRF guard made true and two claims corrected (supersedes 045) | Accepted |
| 047 | The discovery engine may open sockets, and connect scanning is what it may do with them | Accepted |
| 048 | The fingerprint corpus is signed content under a static policy it cannot widen | Accepted |
| 049 | Probes have kinds, and a key exchange is not a payload (supersedes 048 §1 rule 2) | Accepted |
| 050 | The rule engine is closed evaluators and open rules | Accepted |
| 051 | A scope narrowing reaches an in-flight job at its next lease renewal | Accepted |
| 052 | A CSV export refuses over its cap rather than truncating, and export is its own permission | Accepted |
| 053 | The operator SPA is a public static route in the one registry, and its client is a third registry | Accepted |
| 054 | What may live in the repo, now that it is private (hygiene relaxes, good practice does not) | Accepted |
| 055 | The enrollment-token prefix, and its now-half-moot secret-scanning rationale | Accepted |
