---
name: task-status-coverage-claims
description: scan_tasks.status (S42/ADR-093) gates nothing that scans — measured; the hazards are a future status filter in Jobs.Tasks, an unreachable MarkRunning, and a 'completed' claim stronger than the evidence.
metadata:
  type: project
---

Measured 2026-09-11 against `internal/store/jobs.go` after S42 taught `MarkRunning` and
`Terminate` to advance `scan_tasks.status` (ADR-093 decision 3). Probes: a `zz_*_test.go` in
`internal/dispatch` driving the real wire order through `fakeStream`, and one in
`internal/store` driving `Claim` -> `Grant` -> aged lease -> `ExpireLeases` -> re-`Claim`.
Both deleted after use.

## The whole reader set for `scan_tasks.status`

`Jobs.Tasks` is the ONLY code that reads it, into `Task.Status`, which **nothing consumes**.
Not on the wire (`scanpointv1.Task` = task_id, target, fragile), not in `Jobs.Claim`'s
predicates (existence + `authorization_verified` only), not in `PlanScan` (plans from
`scans.status='pending'`, never from tasks), not in `Leases.ExpireLeases`, not in
`SettleIfDone` (counts jobs), not in `internal/correlate`, not in any view, API handler or
console screen — `scan_tasks` appears in NO file under `internal/control`. So status advance
cannot skip, re-scan or duplicate a target. Re-verify that list before accepting any future
"tasks follow the job" change.

**The hazard this created:** `Jobs.Tasks`'s unfiltered read is now load-bearing and nothing
says so. The day someone adds the obvious `AND status IN ('pending','running')` to it, three
things break at once — the assignment silently carries fewer targets than the job has
(under-scan that looks clean, the failure `ErrTooManyTasks` exists to prevent), the mid-scan
`scopeNarrowedForJob` re-check stops covering the dropped targets, and `tasksBelongToJob`
starts rejecting valid observations. Check that first on any `Jobs.Tasks` diff.

## Measured defects (reported, not fixed as of 2026-09-11)

- **`MarkRunning`'s task branch is unreachable in production.** `internal/scanpoint` sends
  exactly one `JobProgress` per job, from `terminate()` via `sendTaskCounts`, i.e. AFTER
  `sendTerminal`. Core's receive loop is serial, so by the time `onProgress` runs the job is
  terminal and `MarkRunning`'s `status='assigned'` predicate matches nothing. Measured: tasks
  go `pending -> completed`, `started_at` NULL on every row, `completed_at` set. The
  integration test passes only because it calls `MarkRunning` directly, in an order the wire
  never produces. ADR-093 decision 3's "MarkRunning moves pending tasks to running" is true of
  the function and false of the system.
- **`completed` is asserted per target from a job-level fact.** `Terminate` writes
  `completed` to every open task when `reason=COMPLETED`, ignoring `JobTerminal.incomplete`
  and the `tasks_completed`/`tasks_failed` counts (`onProgress` discards those entirely).
  Measured: a 3-task job terminating COMPLETED with `incomplete=true` and `tasks_failed=3`
  leaves three rows saying `completed`. The runtime also computes `failed = len(tasks) -
  len(observations)`, so a clean engine exit that observed nothing produces exactly this.
- **The lease sweeper ends jobs and not tasks.** `ExpireLeases` never touches `scan_tasks`.
  Measured: a non-`reassign_safe` job goes `failed` with its task still `pending` (or
  `running`) and no `completed_at` — the ADR's own complaint, surviving on the ADR-012
  fail-loudly path an operator is most likely to be reading. A `reassign_safe` requeue leaves
  a `running` task under a `queued` job, and the re-claim does not reset `started_at`.
- `task_status` has a `skipped` value used by nothing; a cancel/kill records untouched targets
  as `failed`, indistinguishable from ones the engine tried.

Related: [[dispatch-scope-and-kill-gaps]], [[scanpoint-runtime-bypasses]],
[[shutdown-drain-result-loss]]
