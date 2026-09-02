---
name: dispatch-scope-and-kill-gaps
description: Standing gaps in internal/dispatch — Core-side scope check still absent, tag denies dropped fail-open, cancellation has no trigger. Check these first on any dispatch/scanpoint diff.
metadata:
  type: project
---

Rebased 2026-09-02 after the `constraintsFor` / `scopeLists` / `propagateCancellations`
change. **Fixed since the first audit** (do not re-report): `Task.fragile` now travels from
`assets.fragile` via `scan_tasks.asset_id`; `Jobs.Claim` refuses tasks with NULL `target_id`
or `authorization_verified IS NOT TRUE`; `propagateKills` marks `sent` only on successful
queue; `MaxAttempts` bounds retry; policy ceilings now reach the wire as min(platform, policy).

## Still open, highest first

**Core-side scope enforcement does not exist.** `offerWork` builds `constraints` and builds
`wire.Tasks` in the same loop and never compares the two. Nothing anywhere compares
`scan_tasks.task_target` against `policy_scope_rules`. `task_target` is free `text` with no
constraint tying it to its `scan_targets.target_value`, so a task can carry a target_id for an
authorised `192.0.2.0/24` and a `task_target` of anything at all — the new
`TestCancelledScanIsNeitherDispatchedNorLeftRunning` seed does exactly that shape. ADR-024
control 1 requires two sites; Core is site one and it is empty, and `internal/scanpoint` is
still only `doc.go` + `CLAUDE.md`, so site two does not exist either. Forwarding the lists is
not enforcing them.

**Tag denies are dropped fail-OPEN.** `scopeLists` skips `MatchType == MatchTag` before the
allow/deny switch. Dropping a tag *allow* fails closed (empty allowlist). Dropping a tag
*deny* silently deletes an exclusion — `deny tag 'medical'` inside an allowed CIDR reaches the
wire as no exclusion at all. The unit test asserts this behaviour, so it reads as intended.
Allows and denies must not share a drop path.

**`match_type` is unrepresentable on the wire.** `allowed_targets` / `exclusions` are
`repeated string` with no discriminator, and `scopeLists` pushes cidr, hostname and url values
into the same list. A receiver cannot tell them apart; a hostname exclusion is bypassed by
targeting the IP; a url exclusion is meaningless to a network scan point. `match_value` is
`text` with no CHECK and `scopeLists` parses nothing, so `0.0.0.0/0` or an unparseable string
travels verbatim.

**Empty-vs-absent, still undecided, now load-bearing.** `allowed_targets: []` = DENY ALL is
asserted only in a Go unit test comment. `dispatch.proto` does not say it, nothing reads it,
`make safety` is a failing stub. The natural proto3 reading is "unset → do not filter", which
is fail-open. Same unanswered question for `max_rate_pps = 0` (constraintsFor has no floor and
`uint32(*p.MaxRatePPS)` can truncate a huge int to 0) and `window_ends_unix = 0`.

**Policy fields that reach nothing.** `Policies.ForJob` selects 3 of `scan_policies`' 7
meaningful columns. `time_windows` is dropped although `window_ends_unix` and
`WINDOW_EXPIRED` both exist; `allowed_zones` is dropped, so a scan point in a forbidden zone
can claim the job; `allowed_engines` is dropped, Claim filters on scan-point capability only.

**`safety_mode` now passes through with no per-scan opt-in and no audit event.** ADR-021 §36
requires both. `scans` has no opt-in column and `offerWork` records no `AuditEvents`. One
policy flipped to intrusive standing-authorises every scan bound to it, including scheduled
ones.

**Cancellation has no trigger.** Nothing sets `scans.status = 'cancelled'` — no `scans.go` in
`internal/store`, no scan service in `internal/control`. `CancellableFor` and the new Claim
clause cannot fire. Also: `CancellableFor` matches `'cancelled'` only while Claim excludes
`'cancelled','killed'`, so a killed scan's in-flight jobs get no `CancelJob`; `CancelJob` has
no ack message so the 10 s bound is unmeasurable; the inner `JOIN LATERAL` silently drops a
job with no lease row; and once `ExpireLeases` requeues a job (`scan_point_id = NULL`) the
scan point that may still be scanning it is no longer matched by `j.scan_point_id = $2`.

**Constraints are computed at claim time and never re-pushed.** No wire message updates a
running job's scope or rate. Revoking `authorization_verified` or adding a deny rule mid-scan
does not reach in-flight tasks; the only lever is cancellation, which has no trigger.

**Unbounded `ScopeRules`.** No LIMIT, unlike `MaxTasksPerAssignment`. A policy with enough
rules produces a `JobAssignment` over the 4 MB wire cap, failing the Send *after* the job is
assigned and leased — the exact failure `ErrTooManyTasks` exists to prevent, reopened on a
different field.

**Concurrency and adaptive backoff.** `max_concurrent_per_target` is platform-only: an
operator lowering `max_rate_pps` to protect a fragile estate still gets 20 concurrent
connections per host, and there is no fragile concurrency cap — connection count, not packet
rate, is what kills printers. ADR-024's "rate limiting is adaptive during execution" has no
implementation and no wire field.

**Kill switch.** `KillSwitches.Live` is unscoped — every live kill goes to every scan point,
and the wire `KillSwitch` carries only `kill_id`, so scope never travels. Claim's kill clause
handles `tenant` and `scan` but not `zone`. Nothing sets `resolved_at`. `pollInterval = 2s` DB
polls now number two per tick, neither with a query timeout.

**How to apply:** on any `internal/dispatch`, `internal/scanpoint` or engine diff, re-check
these before reading anything else. Separate "wrong now" from "wrong the moment a real engine
lands" — for this codebase almost everything is the latter, and saying so is the useful part.

Related: [[bypass-engine-import-guard]], [[lab-scope-guard-bypasses]]
