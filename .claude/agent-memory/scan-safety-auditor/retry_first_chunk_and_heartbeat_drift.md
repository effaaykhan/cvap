---
name: retry-first-chunk-and-heartbeat-drift
description: submit.go first-chunk RETRY_LATER fix is complete (incl. multi-chunk); no retry constant shadows a config field; HeartbeatTimeout=90s is duplicated as a raw SQL literal in kill.go
metadata:
  type: project
---

Findings from the session-18/HEAD-43ac46d follow-up audit, measured 2026-09-05.

**submit.go first-chunk RETRY_LATER fix (deliver, ACCEPTED-only resumeFrom
advance) is COMPLETE.** Confirmed by measurement:
- The proto3 default-0 ambiguity only bites at chunk index 0 (`0 >= 0`). For a
  LATER chunk getting RETRY_LATER, Core sends `LastChunkAccepted=lastAccepted`
  (only set `if sub.hasAccepted`, ingest.go), so `0 >= 1` is false — no loss even
  pre-fix. Reachable through no other scan-point ack path: ACCEPTED_QUARANTINED /
  DUPLICATE / MALFORMED all `return false` (clear), the drain loop (submit.go
  ~343) never touches resumeFrom, and Core's resume "already ingested" ack
  (ingest.go ~549) is a genuine ACCEPTED.
- Multi-chunk: the SAME bug drops the entire first 2000-obs chunk when a
  MULTI-chunk submission's FIRST chunk hits RETRY_LATER. Pre-fix overlay measured
  `recvdChunks=[[0] [1 2]]`, 2001/4001 delivered (chunk 0 skipped on retry).
  Post-fix delivers 4001/4001, no dupes. The commit framed it as single-chunk but
  the fix covers this too.
- The guard test (TestSustainedRejectionKeepsTheBufferThenDelivers) fails on the
  pre-fix overlay and passes with the fix; its `if keep`→`if !keep` sabotage is
  killed. Fix is load-bearing.

**Target 3 — f_max_retries retry-constant-shadowing-config: NOT FOUND.** No
hardcoded retry/attempt/backoff constant shadows a config field. `MaxAttempts=5`
(store/jobs.go:433, documented execution-plan §5) and `maxJobsPerPoll=5`
(dispatch.go:85) are single-source with no config field; `RetryAfterMs=2000`
(ingest.go x2) is consistent; scan-point ReconnectMin/Max are single-source;
fingerprint `MaxProbesPerPort` is correctly config-driven and clamped to
platform=8.

**But the same DRIFT SHAPE exists off the retry path (Low):**
`dispatch.HeartbeatTimeout = 90*time.Second` (execution-plan §5) is duplicated as
a raw SQL literal `interval '90 seconds'` in store/kill.go:332
(`KillSwitches.Unacknowledged`), because `store` cannot import `dispatch` (cycle).
No test ties them. sweeper.go:151 uses the constant; kill.go uses the literal — if
HeartbeatTimeout is raised, the operator's kill-acknowledgement chase set drifts:
a scan point live-but-quiet (heartbeat >90s but < new timeout, still holding its
lease and scanning) drops out of `Unacknowledged`, so an operator is not told to
chase its unacked kill (ADR-024 control 4). `LiveFor` (delivery) does not use the
window, so delivery and the chase set can disagree after a change. Relates to
[[dispatch_scope_and_kill_gaps]].
