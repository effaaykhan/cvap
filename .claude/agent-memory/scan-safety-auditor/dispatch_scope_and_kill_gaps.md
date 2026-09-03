---
name: dispatch-scope-and-kill-gaps
description: Standing gaps in internal/dispatch and internal/store. The bypasses this file named were fixed in sessions 8e/8f — read the closed list first so they are not re-reported.
metadata:
  type: project
---

Rebased 2026-09-02 after session 8e (`windows.go`, `LiveFor`, `cancel_acks`, migrations
0024/0025, ADR-037). Verified against a live Postgres via `make store-test`.

Amended 2026-09-03: the scan point runtime now exists, so the second enforcement site is
real. `permits`/`scopeMatches` moved out of `scope.go` into `internal/scope` and both sites
call `scope.Permits` — the matcher findings recorded here now apply to BOTH sites at once.
Runtime-side defects live in [[scanpoint-runtime-bypasses]].

## Closed since earlier audits — do NOT re-report

`Task.fragile` travels from `assets.fragile`. `Jobs.Claim` refuses NULL `target_id` and
`authorization_verified IS NOT TRUE`. `propagateKills` marks `sent` only on successful queue.
`MaxAttempts` bounds retry. Policy ceilings reach the wire as min(platform, policy), now
including `max_concurrent_per_target`. **Core-side scope enforcement exists** (`permits` in
`scope.go`, called per task in `offerWork`; `refuseJob` writes `job.scope_refused`). Tag
denies no longer drop fail-open — `scopePlan` fails the job for anything it cannot express.
`MaxScopeRulesPerAssignment` bounds the wire size. Empty-vs-absent is decided and written down
(ADR-037 + proto receiver MUST). `allowed_zones` and `time_windows` are enforced.
`scans.safety_mode` gives ADR-021 its per-scan opt-in and the effective mode is min(policy,
scan). `killed` scans get `CancelJob`. `Jobs.Claim`'s kill clause covers `zone`.

## Fixed in the same session, after the audit — do NOT re-report

All four confirmed bypasses were closed before the change was handed back, each with a
regression test that fails against the old code:

- **DST spring-forward widening.** `windows.go` now builds each boundary through `wallClock`,
  which reports whether the reading it was asked for actually exists that day; a window inside
  a skipped hour does not open at all rather than collapsing into the midnight-crossing branch.
  `TestWindowEnd` covers the spring gap, the day either side, and a window merely spanning it.
- **Forgeable `CancelAck`.** `CancelAcks.Record` is now an `INSERT ... SELECT` conditional on an
  unreleased lease held by that scan point at that epoch, under a scan that is actually stopped.
  A repeat of an ack already held still returns nil, so the honest retry stays distinguishable
  from the forged one. `TestAnUnsolicitedCancelAckIsRefused`.
- **Scan kill lost on lease expiry.** `killCoversScanPoint` (one const, shared by `LiveFor` and
  `Unacknowledged`) and `CancellableFor` key on the lease rather than `scan_jobs.scan_point_id`,
  bounded by `store.StillHoldingGrace` — because `Release`/`ReleaseAny` require `granted`, so a
  lease that expired can never be marked released and an unbounded test would chase it forever.
  `TestAScanKillSurvivesLeaseExpiry`, `TestAReportedTerminalStopsTheCancellation`.
- **v4-mapped CIDR exclusion.** `scopeMatches` unmaps the RULE as well as the target, moving the
  prefix length with it. `TestPermitsIsExclusionFirstAndEmptyDeniesAll`.

Also closed from the "still open" list below: **window close now has a second site** —
`onLeaseRenewal` refuses a renewal once the window has shut, which ADR-012 and invariant 8 turn
into a self-abort with zeroisation. It fails OPEN on a read error, deliberately, so a database
blip cannot mass-revoke the fleet's leases; the start-side check is the one that fails closed.
`TestALeaseIsNotRenewedPastTheMaintenanceWindow`.

Two more, from the same round: `Unacknowledged` was not scoped like `LiveFor` (a zone kill
named the whole fleet as delinquent, forever); and `KillSwitches.Issue` stopped a scan without
setting `cancel_requested_at`, so the only stopped-scan path that exists was the one whose
ADR-024 bound could not be measured. Both fixed. The widest arm of every kill predicate is now
`scope NOT IN ('zone','scan')`, so a `kill_scope` added later fails safe.

## Still open, highest first

**No fragile concurrency cap.** `constraintsFor` clamps `fragile_rate_pps` beneath
`max_rate_per_target` but every task, fragile or not, gets the same
`max_concurrent_per_target`. The diff that added the lever argues in its own comment that
"connection count is what tips a printer over".

**Nothing triggers a kill or a cancellation.** `KillSwitches.Issue`, `KillSwitches.Resolve`,
`Scans.SetSafetyMode` and any writer of `scans.status='cancelled'` / `cancel_requested_at` have
no production caller — tests only. The whole ADR-024 control 4 chain is unreachable from
outside the test suite. Also: `Resolve` un-blocks `Jobs.Claim`, so resolving a kill record
resumes every scan it halted.

**Constraints are computed at claim time and never re-pushed.** True of scope, rate, safety
mode and zones. Revoking `authorization_verified`, adding a deny rule or narrowing
`allowed_zones` mid-scan reaches no in-flight task; a closing WINDOW now does, through the
renewal refusal, and that is the only dimension with a mid-scan lever.

**Matcher edges that survived the move to `internal/scope`.** CIDR boundary arithmetic is
correct (network, broadcast, off-by-one, non-canonical prefixes). An IPv6 ZONE defeats
exclusions outright — `Prefix.Contains` returns false for any zoned address and `Addr`
equality includes the zone. NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) notation of an
excluded v4 address is not unmapped, so it walks past the exclusion when an IPv6 allow
covers it; `Unmap()` handles `::ffff:` only. A trailing-dot FQDN is a different string from
the same name without one.

**`match_type` is still unrepresentable on the wire**, and hostname rules deliberately resolve
nothing — so an allowed hostname covers whatever DNS says at scan time, in either direction.
`allowed_engines` is still selected by nothing. Adaptive rate limiting (ADR-024 control 2) has
no implementation and no wire field.

**A CIDR-shaped `task_target` is refused outright.** `scopeMatches` tries `ParsePrefix(rule)`
first, so a CIDR allow rule only ever matches an *address*; a task whose target is a range
fails `permits` and `refuseJob` terminates the job. Fail-safe, and now stated in
`scan_tasks.task_target`'s column comment (migration 0024) so the first planner that emits a
range sweep reads it before it writes one — but the behaviour is unchanged.

**An unparseable `time_windows` permanently fails every job under that policy** (claimed, then
`constraintsFor` errors, then `refuseJob`). Safe direction, but a typo'd IANA zone name is a
self-inflicted scan outage with `scope_violation_halt` as its reason.

**How to apply:** on any `internal/dispatch`, `internal/store`, `internal/scope` or engine diff, re-check the
confirmed bypasses first, then the open list. Separate "wrong now" from "wrong the moment a
real engine lands" — for this codebase most of it is the latter, and saying which is which is
the useful part. A live dev Postgres is usually up (`docker ps` shows `cvap-postgres-1`);
`make store-test` runs the integration half, and a throwaway `zz_*_test.go` probe in
`internal/store` or `internal/dispatch` is the fastest way to prove a bypass — delete it after.

Related: [[scanpoint-runtime-bypasses]], [[bypass-engine-import-guard]], [[lab-scope-guard-bypasses]]
