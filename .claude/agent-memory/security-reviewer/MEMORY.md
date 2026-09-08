# Security reviewer memory

- [Recurring findings](recurring-findings.md) — 36 defect classes: self-asserted fields, intra-tenant IDOR, unimplemented MUSTs, rolled-back failure counters, pre-auth KDF in a pooled tx, guards defeated by a stdlib rewrite on the way out, state not bound to the browser, size caps the library ignores.
- [Store review harness](store-review-harness.md) — reaching the dev DB, seeding a claimable job, reusing the store/dispatch/api test helpers, why `-race` is unavailable, and what to do when another agent rewrites the code mid-review.
- [Contract-only review posture](contract-only-review-posture.md) — review proto/schema commits for "does it force the secure implementation", not exploitability today.
