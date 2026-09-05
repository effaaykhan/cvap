---
name: fault-matrix-session20
description: Session 20 §6.4 fault-injection matrix (commit c233be0) — all 8 declared mutations kill; the F1a holder/IDOR sub-property is only probabilistically covered and mutation-less
metadata:
  type: project
---

Session 20 (commit c233be0, ADR-056) added the distributed fault matrix F1–F6. Audited 2026-09-05 by re-running every declared sabotage through overlay mutation against the dev DB.

**All 8 declared mutations kill deterministically** (verified, not read): F1a status-gate (jobs.go `status IN`), F1b requeue-everything (leases.go, e2e — overlay binds because ExpireLeases runs in the test process), F2 epoch fence (ingest.go, unit layer), F4 CompletedAt arm (ingest.go), F3 clock_timestamp→now() (leases.go), F6a buffer-HARD (submit.go), F6b dispatch HARD case (dispatch.go), F5 resume skip (submit.go). The shared-test_args risk in ingest_test.go (F2+F4 both declare identical comprehensive `-run` lines) is fine: both mutations kill against the shared 3-test set.

**Finding (Medium, test-quality not production): the F1a holder/IDOR sub-property is only probabilistically asserted and carries no mutation.**
- Terminate's `AND scan_point_id = $3` (the IDOR fix — one scan point must not complete another's job) has NO declared mutation. The commit says it can't carry a single-line anchor (its WHERE line is shared with MarkRunning) — true.
- Its only guard is the `byOther==0` assertion in F1a. A genuinely valid holder-less query (`$3::uuid = $3::uuid`, holder restriction dropped, query still valid) SURVIVES ~25% of runs (measured 3/12 survived). Catch depends on which racer wins the row-lock race.
- Naive holder-clause mutations mislead: dropping `$3` entirely gives a param-count error; `$3 IS NOT NULL` gives SQLSTATE 42P18 (untyped param). Both "kill" via winners=0 as artifacts, NOT via the IDOR path. Only a type-cast form exercises the real property — and it flakes.
- The commit's claim that "the same clause's fencing twin is mutation-covered on Leases.Renew (F3)" is inaccurate: F3 mutates Renew's expiry fence (`clock_timestamp()`), not its holder clause (`holder_scan_point = $4`). Neither holder clause has a declared mutation.

**Sound items confirmed:** F2 reason-string assertion is robust (checkEpoch emits the literal "superseded lease epoch…"; distinguishes from zone/task quarantine). accepted==0 is a valid "not processed" proxy (all pipeline read paths in observations.go filter `ingest_state='accepted'`). F2 e2e correctly carries no mutation (checkEpoch runs in the separately-built cvap-core binary; overlay can't reach it). Two dropped cases genuinely unit-covered (TestUnissuedEpochAndWrongHolderQuarantine); holder derives from `enrollment.PeerFingerprint` (TLS cert), so impersonation is unreachable. F6b negative is meaningful (recovery step proves claimability). F3 scenario faithful (transaction_timestamp fixed pre-expiry, clock_timestamp advances past).

**Resolved (same session, before push):** the holder/IDOR sub-property now has a deterministic
sequential test, `TestTerminateRefusesANonHolder` (internal/store/fault_completion_integration_test.go) —
a non-holder's Terminate on an assigned job is refused and the job left untouched. Verified it
kills a targeted holder-less Terminate predicate 3/3 (where the race caught it ~9/12). It carries
no declared mutation because `scan_point_id = $3` is textually identical across five jobs.go
queries (no unique single-line anchor — the ADR-056 case). The inaccurate "F3 covers the holder
twin" claim was removed from the F1a comment.
