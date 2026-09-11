# Security reviewer memory

- [Recurring findings](recurring-findings.md) — 41 defect classes: self-asserted fields, intra-tenant IDOR, rolled-back refusal records, guards defeated on the way out, size caps the library ignores, non-CLOEXEC fds inherited by sibling engines, trust material composed per-host and checked host-agnostically.
- [Store review harness](store-review-harness.md) — reaching the dev DB, seeding a claimable job, reusing store/dispatch/api/scanpoint test helpers, spawning a real child engine, why `-race` is unavailable, and what to do when another agent rewrites the code mid-review.
- [Contract-only review posture](contract-only-review-posture.md) — review proto/schema commits for "does it force the secure implementation", not exploitability today.
