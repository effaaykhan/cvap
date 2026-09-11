# Security reviewer memory

- [Recurring findings](recurring-findings.md) — 42 defect classes: self-asserted fields, intra-tenant IDOR, rolled-back refusal records, guards defeated on the way out, size caps the library ignores, non-CLOEXEC fds inherited by sibling engines, trust material composed per-host and checked host-agnostically, evidence written on a branch that disclaims authority and read by a trust root.
- [Store review harness](store-review-harness.md) — reaching the dev DB, seeding a claimable job, reusing store/dispatch/api/scanpoint/correlate test helpers, driving the lease sweeper, proving a finding is a regression, why `-race` is unavailable.
- [Contract-only review posture](contract-only-review-posture.md) — review proto/schema commits for "does it force the secure implementation", not exploitability today.
