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
