---
name: dispatch-scope-and-kill-gaps
description: Standing gaps in internal/dispatch — zero scope-enforcement sites, kill switch droppable, fragile never set. Check these first on any dispatch/scanpoint diff.
metadata:
  type: project
---

Found auditing commits `3caad18` (Dispatch) / `11fc063` (Ingest) on 2026-09-02. All are inert
while no engine sends packets; every one is live the moment a runtime exists.

**Scope: zero enforcement sites, not two.** No Go code anywhere reads `policy_scope_rules` or
`scan_targets.authorization_verified` (grep both — empty). `Jobs.Claim` + `Jobs.Tasks` hand
`scan_tasks.task_target` to a scan point with no authorisation join, and `scan_tasks.target_id`
is nullable so a task need not trace to an authorised target at all.
`defaultConstraints()` sends `allowed_targets` and `exclusions` empty while
`policy_scope_rules` holds exactly that data.

**Empty-vs-absent is undecidable on the wire.** `ScanConstraints.allowed_targets` is proto3
`repeated` — no presence. Empty must mean **deny all** at the scan point, or the check
"authorises anything not denied", which the proto comment itself says is not a scope check.
Same for `window_ends_unix = 0` (1970 = expired, or = no window?). Decide and write it into
the proto comment before a runtime reads these.

**Kill switch is droppable and unmeasured.**
- `propagateKills` sets `sent[k.ID] = true` *before* `s.send`, and `s.send` has a `default:`
  that drops when the 64-slot outbound queue is full. Dropped kill is never retried on that
  stream. The scan point that has stopped reading is the one you most need to kill.
- "Kills first" is only first *within a tick*; both go to the same channel, so a kill queues
  behind up to 63 job messages. No priority path.
- A live kill does not stop `offerWork`. Core kills in-flight work and assigns more 2s later.
- Nothing ever sets `kill_switches.resolved_at` — no `Resolve` exists. `Live()` grows forever
  and every reconnect replays every kill ever issued. `fixtures.sql` seeds a permanently-live one.
- `KillSwitches.Unacknowledged` filters on **current** `scan_points.status`, not status at
  `issued_at`, so a scan point that disconnects after issue silently leaves the set and the
  bound looks met. It also returns a set, never a latency — nothing computes
  `acked_at - issued_at` against ADR-024's 10 s.
- Wire `KillSwitch` carries only `kill_id`. `kill_scope` has `tenant|zone|scan` but none of it
  travels, so a scan-scoped kill either over-halts the tenant or is ignored.
- `pollInterval = 2s` DB poll with no query timeout is the poll boundary ADR-005 rejected for
  exactly this message. A hung DB blocks propagation indefinitely.

**`Task.fragile` is never set.** `offerWork` builds `Task{TaskId, Target}` only. `assets.fragile`
exists (migration 0007) but `scan_tasks` has no path to an asset, so the join does not exist in
the schema either. Every task ships `fragile=false` → 50 pps instead of 10 against a printer/SCADA/medical device.

**Policy ceilings never reach the wire.** `defaultConstraints()` is a hardcoded literal
matching ADR-024 exactly, but ignores `scan_policies.max_rate_pps` and `safety_mode`. When
wired it must be `min(platform_default, policy)`, never `policy` — the DB `CHECK (<= 1000)` is
a second copy of the number and will drift.

**Ingest ignores two stated MUSTs.** `toObservations` parses `zone_id` and never validates it
against `scan_points.zone_id` (ingest.proto: "MUST be quarantined"; migration 0002 comment
repeats it). `task_id` is never checked to belong to the submitted `job_id`.

**How to apply:** on any diff to `internal/dispatch`, `internal/scanpoint` or a new engine,
re-check each of these before reading anything else. The report to the parent agent should
separate "wrong now" from "wrong the moment a real engine lands" — for this codebase almost
everything is the latter, and saying so is the useful part.

Related: [[bypass-engine-import-guard]]
