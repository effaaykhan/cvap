# Security reviewer memory

- [Recurring findings](recurring-findings.md) — self-asserted trust fields, proto `String()` secret leaks, overclaiming comments, and why proto fixes must be additive.
- [Store review harness](store-review-harness.md) — how to reach the dev DB, write throwaway PoCs in `package store`, and why `-race` is unavailable.
- [Contract-only review posture](contract-only-review-posture.md) — review proto/schema commits for "does it force the secure implementation", not exploitability today.
