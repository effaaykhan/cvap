# internal/dispatch

Job broker, Dispatch service, Ingest service.

Rules:

- **The broker is never reachable from a scan point** (ADR-004). Scan points hold an
  outbound stream to Dispatch, which pulls on their behalf. They never learn the broker's
  protocol, address or topic names.
- Dispatch and Ingest are separate services (ADR-005). Do not fold result submission into
  the dispatch stream: a multi-megabyte upload there head-of-line blocks job assignment.
- Job claim is `SELECT ... FOR UPDATE SKIP LOCKED` in the same transaction as the lease
  (ADR-003). Introduce a broker only with a measured reason.
- Every lease carries a monotonic epoch. Reassignment happens only after demonstrable
  expiry, with a new epoch (ADR-012).
- **Results are always stored, never discarded** (ADR-026). A superseded epoch yields
  `ACCEPTED_QUARANTINED`: stored, withheld from the finding pipeline, surfaced to an
  operator. `reassign_safe` governs retry, not retention.
- Ingest is idempotent on `submission_id` at the boundary, not downstream in the finding
  pipeline.
- Backpressure is explicit and flows both ways. A saturated Core slows scan points down; it
  never lets them queue unboundedly inside a customer's network. Only the dispatch-side
  signal can stop the buffer growing, because only dispatch can stop Core handing out work.

## Observations land pending

Every observation is inserted `pending` and promoted once — to `accepted` or `quarantined` —
by the terminal ack, in the **same transaction as the final epoch check**.

Two states were not enough. A submission arrives in chunks and its epoch can be superseded
midway: with rows landing `accepted`, chunk 0 is readable by the finding pipeline before
chunk 5 reveals the supersession, and quarantining retrospectively narrows that window
without closing it. Landing `pending` closes it — the pipeline filters `accepted`, so an
in-flight submission is invisible to it **without the pipeline knowing submissions exist**.
No join to remember on the largest table in the system, and no window.

`ingest_state` is a **ratchet**, enforced by a trigger in migration 0020: `pending` may be
promoted once, and `accepted`/`quarantined` are terminal. A grant cannot express "ingest may
set this and the pipeline may not" — both run as `cvap_app` — but a ratchet can, because
un-quarantining is not an operation anything legitimately performs.

An abandoned upload leaves rows `pending` forever. That is correct: the results were never
attested complete, and deleting them would discard the record of what a job touched. It needs
a **metric**, not a cleanup — `Observations.PendingOlderThan` is that query, and a health
surface should carry it.

## Identity, and what is never trusted

Resolved from the TLS peer certificate on both streams, through the ADR-033 pre-tenant class.
Nothing in any message asserts who the sender is. `Hello.scan_point_id` is an echo and a
mismatch closes the stream.

`credentials_zeroised` and `observed_rate_pps` are **attestations, not controls**. A
compromised scan point can set either and lie. They exist to catch *our* bugs: a `JobTerminal`
without `credentials_zeroised` raises an audit event, because an invariant nothing asserts is
one nothing notices the loss of — and `observed_rate_pps` is never read as the rate actually
sent.

## The sweep, and why it is not optional

`Leases.ExpireLeases` carries ADR-012 entirely: a `reassign_safe` job whose lease ran out goes
back to the queue, and one that is **not** `reassign_safe` fails with `lease_lost` plus an
operator escalation, because duplicating active or intrusive work harms the target. A security
review found it had **no caller**. The property was written, documented and unit-tested, and
nothing in Core would ever have run it — so a scan point that died mid-job left that job
`running` forever. `HeartbeatTimeout` was in the same state: a constant, a comment, and no
comparison against `last_heartbeat` anywhere.

`Sweeper` is that caller, and it is periodic because the event it reacts to is the **absence**
of one. A dead scan point sends nothing, and the stream closing is not the signal either — a
partitioned scan point holds its lease and keeps scanning while its stream is long gone.

- The escalation audit event is written in the **same transaction** as the expiry. One recorded
  afterwards is one a crash can drop, leaving a job marked `failed` and nobody told to look.
- `Sweeper.Interval` must stay below `store.LeaseTTL`. Slower than the TTL and an expired lease
  stays `granted` for up to an interval, delaying the escalation on a job that must not retry.
- `Run` never returns an error. A supervisor that restarted the process on a transient database
  failure would turn a blip into an outage of the thing enforcing ADR-012.
- The tenant enumeration it needs is the single unscoped read in `internal/store`
  (`DB.ActiveTenantIDs`, ADR-036). A sweep has no tenant to inherit.

**Registering Dispatch without starting the sweeper reintroduces the finding.** It is listed
with the TLS and keepalive requirements in the package doc for that reason.

## Constraints are min(platform, policy)

ADR-024 control 2 is "a policy may LOWER the ceiling and may never RAISE it".
`defaultConstraints()` returned the platform table verbatim, so a policy asking for 50 pps was
handed 1,000 — twenty times what its operator asked for, against an estate they had reason to
be careful with. `constraintsFor(policy, rules, now)` takes the minimum, which honours both
halves in one expression and ignores rather than trusts a policy value above the ceiling.

The per-target limits clamp beneath the per-scan-point rate. A `max_rate_per_target` above the
whole scan point's budget is not merely meaningless — it tells a runtime it may send ten times
the policy rate at a single host, which is the one place it matters most. `fragile_rate_pps`
clamps again beneath that, since control 3 caps rate *regardless* of what the policy permits.

`max_concurrent_per_target` is the second lever, added in migration 0024, and it is not a
derivative of the rate: a host answering 20 simultaneous connects at 5 pps is under more
pressure than one answering a single connection at 50 pps, and connection count is what tips a
printer over. An operator who lowered `max_rate_pps` to protect a fragile estate was still
being handed 20 concurrent connections per host. Lower-only, like the rest of the table.

`safety_mode` is not a quantity, so it is not minimised arithmetically — but it is still
reduced, on ADR-021's other axis. **The policy sets the ceiling and the scan opts in beneath
it**, and `intrusive` travels only when `scan_policies.safety_mode` and `scans.safety_mode`
both say so. Before `scans.safety_mode` existed there was nothing to opt in with, so one policy
flipped to intrusive standing-authorised every scan bound to it, including scheduled ones
nobody looked at again — the failure ADR-021 was written against. Hardcoding `safe` was the
opposite failure and looked like everything working.

`store.Scans.SetSafetyMode` is the writer: it refuses an opt-in above the policy, refuses one
after the scan has started, and records the ADR-021 audit event in the same transaction.
Nothing calls it yet — the operator API is a later session. `offerWork` writes a second event,
`job.intrusive_dispatched`, when intrusive work actually goes out. The two are different facts:
the first records what an operator authorised, the second what Core dispatched and to which
scan point. **Neither can fire today** — the second needs `scans.safety_mode = 'intrusive'`, and
nothing in production writes the `scans` table at all. Intrusive is currently unreachable,
which is the safe direction and is not the same as the control working.

## Maintenance windows are evaluated at Core, and only their end travels

`scan_policies.time_windows` was read by nothing, while `ScanConstraints.window_ends_unix` and
`TerminationReason.WINDOW_EXPIRED` both existed — a policy could carry a window, the wire could
carry its end, a scan point could report hitting it, and no code connected the three.

The recurring schedule never leaves Core. `internal/dispatch/windows.go` evaluates it and puts
one instant on the wire, so a scan point's clock drifting cannot widen a window and the
encoding stays Core's business. The encoding is documented on the column in migration 0024.

**A job outside its window is not claimed, rather than claimed and released.** `Claim` takes
the currently-closed policy ids and excludes them, because releasing would increment `attempt`
on every two-second poll and hit `MaxAttempts` inside ten seconds — the maintenance window
would destroy the scan it was written to protect. Both the claim predicate and
`window_ends_unix` are computed from **one** `now` per pass, so the two cannot disagree about
whether a window is open.

A window that cannot be parsed is deliberately *not* excluded: the job is claimed,
`constraintsFor` refuses it, and `refuseJob` ends it with an audit event naming the policy. A
scan that stops has to say so.

**The window has two enforcement sites, like the target allowlist.** Core refusing to *start* a
job is only half of it — a job claimed at 03:59 under a `22:00–04:00` window renewed its lease
every 20 s indefinitely, and the only thing that would ever have stopped it was
`window_ends_unix` on the wire, in a runtime that does not exist yet running a build we do not
control. That is the "enforce at the Scan Point only" alternative ADR-024 rejected.
`onLeaseRenewal` refuses a renewal once the window has closed, which invariant 8 and ADR-012
turn into a self-abort with credential zeroisation — a stronger stop than asking. That check
fails *open* on a read error, and it is the one place in this package that should: a database
blip must not mass-revoke every lease in flight. The start-side check fails closed, because
withholding work is not the same as stopping it.

## Zones are a claim predicate, not advice

`scan_policies.allowed_zones` was selected by nothing, so a scan point in a forbidden zone
could claim the job and an operator restricting a scan to their DMZ had written a comment. It
is now a predicate inside `Jobs.Claim`, with the zone read from `scan_points` and never from
the stream.

## Empty means the opposite thing in the two families of list (ADR-037)

`allowed_targets` enumerates **permission**: empty denies everything, because the safe answer
to "where may this scan reach" is nowhere. `allowed_zones` and `time_windows` enumerate
**constraint**: empty is unrestricted, because an unset restriction is no restriction — and
every policy row that exists defaults to `'[]'`, so the other reading would stop the fleet on
the migration that enforced them. Do not normalise these to one convention; ADR-037 is why.

**`allowed_targets: []` means DENY ALL.** Empty and absent are indistinguishable in proto3, so
they must mean the same thing, and for a field whose other reading is "scan anything" the safe
reading is the only defensible one. Core therefore has to populate it: `scopePlan` fills it
from `policy_scope_rules`, and both wire fields were previously left empty. `scopePlan` is
that function.

**Anything that cannot travel fails the job — allows and denies share no drop path.** The
first version skipped `tag` rules before looking at their effect, which a safety audit showed
was fail-closed for an allow and fail-**open** for a deny: `allow 10.10.0.0/24, deny tag
medical` produced a non-empty allowlist, so the job dispatched with no warning at all and the
exclusion protecting the medical devices inside that range reached neither enforcement site.
ADR-024 says exclusions take precedence over allows, and a precedence you can delete by
choosing a match type is not one. `scopePlan` now returns an error for a tag rule, an
unparseable CIDR, an empty hostname or an unknown match type, and `refuseJob` ends the job with
`scope_violation_halt` and a `job.scope_refused` audit event.

**Core checks the targets too — that is site one of control 1, and it was empty.** Core
computed the allowlist, put it on the wire, and compared nothing against it, so enforcement
rested entirely on a scan point runtime that does not exist yet. That is the
"enforce at the Scan Point only" alternative ADR-024 explicitly rejected, arrived at by
omission. `permits` evaluates every `task_target` before the assignment is built: exclusions
first and they win outright, then the allowlist, with addresses compared after `Unmap()` so
`10.10.0.5` also excludes `::ffff:10.10.0.5`. Nothing resolves DNS on either side — a
resolution done at planning is a different answer from the one the scan point would get, and an
allowlist that depends on which side asked is not an allowlist.

The refusal is terminal and audited rather than logged. A job Core refuses is refused
identically on every poll, so leaving it claimable is a two-second loop that goes quiet after
`MaxAttempts` and takes the reason with it — and an operator reads the audit log, not Core's
stdout.

## Cancellation is the narrow half of control 4

A kill switch halts the fleet. `CancelJob` stops one runaway scan and leaves everything else
running, and the difference matters: a stop button that costs every other customer's scan is
one people negotiate with rather than press.

The trigger is `scans.status` — no new column and no second source of truth. **Both** stopped
statuses, not just `cancelled`: `Jobs.Claim` has excluded `cancelled` and `killed` from the
outset, so a killed scan stopped being handed out while its in-flight jobs were told nothing —
the one state where the scan is most demonstrably still touching the estate. Both halves are
needed and either alone is not a cancellation:

- `propagateCancellations` sends `CancelJob` for in-flight jobs, on the **urgent** channel ahead
  of any assignment, marking sent only when the message was actually queued (a scan point with a
  full outbound queue is the one not draining messages, and therefore the one whose runaway job
  most needs stopping).
- `Jobs.Claim` refuses to dispatch a cancelled scan's remaining queued jobs. Without it, Core
  halts the in-flight work and hands out the rest two seconds later, forever.

`CancelJob` carries the lease epoch so it names the incarnation Core means, not whatever is
running under that job id after a reassignment.

**`CancelAck` closes it.** ADR-024 requires `KillAck` because "a 10-second bound Core cannot
measure is not a control", and that argument does not weaken when the blast radius narrows:
"cancellation sent" was the last thing Core knew, and a scan point that dropped the message
looked exactly like one that halted. `cancel_acks` (migration 0025) mirrors `kill_acks`;
`CancelAcks.Unacknowledged` is the set an operator chases and `CancelAcks.ForScan` is the
latency. Latency is `nil` rather than zero when `scans.cancel_requested_at` is unset, because
reporting an unmeasured bound as `0s` is a gate that silently passes.

## The kill switch is narrowed by Core, never by the receiver

`KillSwitches.LiveFor` replaces an unscoped read that sent every live kill to every scan point.
A zone kill therefore halted the whole fleet, and the receiver had nothing to filter on — the
only safe reading of a bare `kill_id` is "halt everything".

Delivery is narrowed at Core because a scan point must not be able to decide that the message
stopping it does not apply to it (ADR-020). `KillSwitch.scope` then says how much of what that
scan point holds to halt, and `KILL_SCOPE_UNSPECIFIED` means everything — an older Core does
not set the field, so the zero value has to be what a bare `kill_id` meant.

A **scan**-scoped kill halts nothing wholesale. `KillSwitches.Issue` marks the scan `killed` in
the same transaction, which turns its in-flight jobs into per-job `CancelJob` messages that
name the job and the epoch, and stops its queued ones being claimed. `Jobs.Claim`'s kill clause
covers all three scopes; `zone` was missing, so a zone kill halted the zone's running jobs and
dispatch handed the same scan points fresh ones two seconds later.

**Delivery and the acknowledgement set are one predicate** — `store.killCoversScanPoint`, used
by `LiveFor` and `Unacknowledged`. They were written separately and immediately disagreed: a
zone kill delivered to one scan point reported every other one in the tenant as delinquent,
forever, for a message Core never sent them. That is worse than no measurement, because a scan
point that genuinely dropped the kill becomes indistinguishable from the ones never covered.

**Both that predicate and `CancellableFor` key on the LEASE, not on `scan_jobs.scan_point_id`.**
`ExpireLeases` nulls `scan_point_id`, so a scan point that partitioned while scanning stopped
matching at the exact moment it became the thing an operator most needs to stop. Bounded by
`store.StillHoldingGrace`, because `Release` and `ReleaseAny` both require `granted` — once a
lease has expired, *nothing* can mark it released, so an unbounded test would chase that job
for the life of the tenant.

The widest arm of every kill predicate is `scope NOT IN ('zone','scan')` rather than
`scope = 'tenant'`, so a `kill_scope` a later migration adds is delivered to everyone and
blocks every claim until someone teaches the predicate about it. That matches `killScope()`'s
documented fail-safe, whose default branch was otherwise unreachable.

## A host job is credentialed or it is refused (ADR-091)

`offerWork` completes a `host` job's assignment through `credentialedAssignment`: the policy's ssh
profile (`CredentialProfiles.SSHForJob`), its `username` as `JobAssignment.cred_user`, and the trust
material as `known_hosts` in the `internal/hostkeytrust` shape — **per task**: the operator's pinned
lines that name that task's address when the profile has a pin, otherwise the SHA256 fingerprint CVAP
observed for that address (`AssetIdentityKeys.SSHHostKeyFingerprintsAt`, one token of one shape —
a stored value with an embedded newline once composed a line for another host). A task with neither
refuses the **whole job**; there is no per-host trust-on-first-use, and a pin for one host is never
trust for another. Every refusable step runs before the secret is resolved.

The secret is resolved last (`credsource.Resolver`, installed by `UseSecretResolver`; a Core without
one refuses every host job naming `CVAP_CORE_SECRET_FILE_ROOT`), recorded as a `credential_grants` row
and a `credential.granted` audit event (`trust_source` carries the same word the wire does) in the
claim's transaction, and sent as a `CredentialGrant` **immediately behind its assignment on the same
channel** — the runtime drops a grant for a job it is not running. **Every exit that is not a Send
erases the material**: a transaction that rolls back after `Resolve` (the deferred discard covers
grants never queued), an assignment refused by a full queue (its grant is discarded, never sent), a
grant refused by the queue, a grant still queued when the stream dies (`Connect` waits for the pump
and drains both channels), and — once `stream.Send` returns, either way — the send loop itself. The
first version's deferred discard ran when `offerWork` returned, before the send loop had dequeued the
grant, so the runtime would have received zeros; `credgrant_test.go` reads the bytes at `Send` and
caught it. Refusals are terminal (`engine_failure`) with a `job.credential_refused` audit event, for
the reason `refuseJob` gives. `onTerminal` sets `credential_grants.zeroised_at` only from the
runtime's attestation and only for grants delivered to the attesting scan point's certificate; a
terminal without it leaves the row open, which is the state an operator should see.
