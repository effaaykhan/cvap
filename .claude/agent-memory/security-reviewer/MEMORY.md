# Security reviewer memory

- [Recurring findings](recurring-findings.md) — 26 defect classes: self-asserted fields, intra-tenant IDOR, unimplemented MUSTs, stop-races-start, rolled-back failure counters, pre-auth KDF inside a pooled tx, oracles reopened by the status code.
- [Store review harness](store-review-harness.md) — reaching the dev DB, seeding a claimable job, reusing the dispatch/ingest test helpers, and why `-race` is unavailable.
- [Contract-only review posture](contract-only-review-posture.md) — review proto/schema commits for "does it force the secure implementation", not exploitability today.
