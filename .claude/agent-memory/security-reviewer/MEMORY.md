# Security reviewer memory

- [Recurring findings](recurring-findings.md) — 18 defect classes: self-asserted fields, intra-tenant IDOR, unimplemented contract MUSTs, narrowed fan-outs, unsolicited acks, unbounded per-poll parsing.
- [Store review harness](store-review-harness.md) — reaching the dev DB, seeding a claimable job, reusing the dispatch/ingest test helpers, and why `-race` is unavailable.
- [Contract-only review posture](contract-only-review-posture.md) — review proto/schema commits for "does it force the secure implementation", not exploitability today.
