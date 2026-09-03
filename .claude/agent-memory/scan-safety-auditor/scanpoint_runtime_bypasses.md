---
name: scanpoint-runtime-bypasses
description: Confirmed defects in internal/scanpoint's terminal path, kill window and rate shape — the second enforcement site. Re-test these first on any runtime diff.
metadata:
  type: project
---

The scan point runtime landed 2026-09-03 (`runtime.go`, `job.go`, `enginehost.go`,
`submit.go`, `cmd/cvap-engine-noop`, `test/e2e`). Scope enforcement moved to
`internal/scope`, shared by Core and the runtime; `internal/scope/scopetest` is the
decision table. All of the below were reproduced with throwaway probes in
`internal/scanpoint` (package-internal, so `rt.jobs` and `job.host` are reachable) using a
shell script as the engine binary — that is the fastest harness for this package and it
does not need Postgres.

## FIXED in the same session, after the audit — do NOT re-report

Every "Confirmed" item below was closed before the change was handed back, each with a
regression test. Read this section first; the detail underneath is kept because it records
what the failures looked like, not because they are still live.

- **Terminal path races engine spawn (C1).** `host` and `cancel` are now built in
  `onAssignment`, before the job enters the table and before any goroutine runs, so the
  terminal path can never find them nil. `stop()` records the request with no process yet and
  `start()` refuses with `errStopBeforeStart`. `TestAStopBeforeStartRefusesTheSpawn`.
- **Superseding assignment ran two engines (C2).** `onAssignment` now waits on
  `existing.done` after aborting, and `terminate` deletes from the table only if it still
  holds THAT job pointer, so a superseded incarnation cannot delete its replacement.
- **Shutdown stopped nothing (C3).** `Run` defers `shutdown()`, which aborts every job and
  waits; `cmd/cvap-scanpoint` then drains the submitter on a fresh context and names what is
  left if it cannot.
- **`grace_ms` unbounded (C4).** `MaxStopGrace = 9s`, clamped in both `onCancel` and
  `stop()`. `TestTheGraceIsBoundedAtTheReceiver`.
- **No runtime rate ceiling (H1) and fragile depending on Core (H2).** `job.budget()` takes
  min(what Core sent, ADR-024's platform value) and holds its own copies —
  `PlatformMaxRatePerTarget`, `PlatformFragileRatePPS`, `PlatformMaxConcurrentPerTarget`,
  `PlatformConnectTimeoutMS`. Zero from the wire means the platform default, never
  "unlimited". `TestPlatformCeilingsAreAppliedAtTheRuntime`.
- **`os/exec` reachable through the engine exception (H5).** `isException` matches exactly
  rather than by prefix; verified by dropping an `os/exec` import into
  `cmd/cvap-engine-noop` and watching the guard fail.
- **The conformance claim was false.** `internal/scanpoint/scope_conformance_test.go` now
  exists and drives `engineHost.authorise` over `scopetest.Cases`, not `scope.Permits`.
- **`authorise` leaked the exclusion list.** The reason no longer travels to the engine, and
  every answer is a refusal once a stop is under way.
- **Engine inherited the whole environment.** `engineEnv()` gives it PATH, HOME, TZ, LANG and
  nothing else, on both the job spawn and capability discovery.
- **Double reap / pid reuse.** `wait()` is the only caller of `cmd.Wait()` and closes
  `reaped`; `stop()` selects on it.
- **Unbounded observation accumulation.** Capped at `MaxJobObservations` /
  `MaxJobObservationBytes`, and truncation sets `incomplete` rather than being silent.
- **One malformed observation destroyed a job's results.** `toWire` applies Core's own
  predicates at the engine boundary, drops the offender, and counts it into `incomplete`.
- **Scope matcher edges**: IPv6 zone (`WithZone("")`) and trailing-dot FQDN are closed, with
  cases in `scopetest`. NAT64/6to4 is NOT — see below.
- **Rotation** now refreshes the live TLS config via `GetClientCertificate` reading from disk
  per handshake, and keeps `key.pem.prev`/`cert.pem.prev` so a crash between the two renames
  cannot brick the scan point.

## Still open after the fix pass

- **NAT64 and 6to4 notation.** `internal/scope` unmaps `::ffff:` only, so `64:ff9b::c000:205`
  and `2002:c000:0205::` still walk past an exclusion of `192.0.2.5` when an IPv6 allow covers
  them. Needs a decision on whether a translated address IS the v4 host for scope purposes.
- **`window_ends_unix` (H3).** dispatch.proto makes stopping at that instant a runtime MUST;
  nothing implements it, and `WINDOW_EXPIRED` is still produced by nothing.
- **`safety_mode` (H4)** reaches the runtime and dead-ends: `enginewire.ToEngine` has no field
  for it, so ADR-021's axis never reaches the component that would run an intrusive check.
- **Constraints captured once, never re-pushed.** A deny rule added mid-scan reaches no
  running engine.
- **`tasks_completed` counts observations, not tasks.**
- **`internal/enginewire` sits outside the engine import guard's roots**, so its own imports
  are never walked — the likeliest place someone later adds a socket.

## Original findings, for the record

## Confirmed, reproduced 2026-09-03

**The terminal path races engine spawn, and `sync.Once` makes it silent.**
`onAssignment` installs the job then `go r.runJob`; `runJob` sets `j.cancel` and `j.host`
only after that. Anything reaching `abort`/`onCancel` in between finds both nil, stops
nothing, and `terminate` deletes the job from `r.jobs`. `runJob` then spawns the engine
anyway — `engineHost.start` never consults `stopRequested`, and its `ctx` parameter is
unused. The result is an engine with no entry in the job table: no cancel, no kill switch,
no `watchLeases`, no renewal can reach it, and when it finishes `finish` loses the
`beginAbort` race and its observations are never submitted. Core is told CANCELLED with
`tasks_failed` while the work actually ran to completion.

**A superseding assignment runs two engines for one job.** In the `epoch >` branch
`onAssignment` calls `abort(existing)`, which returns instantly if an abort is already in
flight (`beginAbort` false) — so the old engine is never stopped, the new one starts
alongside it, and when the old abort's `terminate` finally runs it deletes the job id,
orphaning the NEW incarnation. Two engines, same targets, neither stoppable.

**Nothing stops an engine on shutdown.** `jobCtx` is created and cancelled but nothing
watches it; `exec.Command` deliberately carries no ctx; `Run` returns on ctx without
aborting jobs. SIGTERM to `cvap-scanpoint` exits after a 5 s drain and leaves engine
process groups (`Setpgid`) running. `cmd/cvap-scanpoint/main.go`'s claim that jobs
"self-abort through the same path lease loss uses" is not true of any code path.

**`CancelJob.grace_ms` is unbounded at the receiver.** `onCancel` converts it straight to
a duration and `stop` waits that long before SIGKILL. ADR-024 marks the 10 s propagation
bound "not adjustable" and the proto comment says the field is "bounded by" it — nothing
enforces that. Core sends 5000 today, so this is a receiver-side MUST that is unimplemented
rather than a live overrun.

**The runtime applies no rate ceiling of its own.** `job.budget()` forwards
`max_rate_per_target` verbatim — no clamp against ADR-024's 50/10 — and `max_rate_pps`
(the 1,000 pps per-scan-point ceiling) is read by nothing in the package. In-flight jobs
are unbounded (`maxJobsPerPoll = 5` bounds a poll, not the total), so the aggregate is
50 × N with no accounting anywhere. `internal/scanpoint/CLAUDE.md` claims the runtime
"allocates slices … never allocating more in aggregate than the platform ceiling"; there is
no aggregate. Also: the enginewire budget fields are `omitempty`, so a zero ceiling reaches
the engine as an ABSENT field rather than as zero.

**`window_ends_unix` and `safety_mode` reach the runtime and are discarded.** dispatch.proto
says a runtime reaching the window instant MUST stop and terminate `WINDOW_EXPIRED`; no
runtime path produces that reason. `safety_mode` has no field in `enginewire.ToEngine` at
all, so ADR-021's safe/intrusive axis dead-ends at the runtime. `Task.Fragile` does travel.

**Scope data does reach the engine.** The `authorise` reply carries `Reason`, which is
`"excluded by scope rule <rule>"` verbatim — an engine can enumerate the exclusion list one
query at a time. `pump` also keeps answering `authorise` with permitted=true after `stop`
has been requested.

**Unsynchronised job fields.** `j.epoch` (written by `onLeaseGrant` on the receive loop),
`j.host` and `j.cancel` are read from abort/cancel goroutines with no lock — `j.mu` guards
only `expires`/`aborting`/`reason`. Real Go data races; CI's `go test ./... -race` will not
catch them because nothing in the package exercises the concurrency. `-race` needs
`CGO_ENABLED=1` and gcc, which this box does not have.

**`stop()` signals a pid it may already have reaped.** `syscall.Kill(-pid, …)` after
`cmd.Wait()` has run targets a recycled pid's process group; `stop`'s `Process.Wait`
goroutine also races `wait`'s `cmd.Wait`.

## Scope matcher edges (internal/scope, both sites)

CIDR boundary arithmetic is correct — network, broadcast, off-by-one either side, and
non-canonical prefixes all behave. What does not:

- **An IPv6 zone defeats exclusions.** `netip.Prefix.Contains` is documented to return false
  for any zoned address, and `Addr` equality includes the zone. Allow `fe80::1%eth0` +
  exclude `fe80::1` = PERMITTED.
- **NAT64 and 6to4 notation.** `Unmap()` handles `::ffff:` only, so `64:ff9b::c000:205` and
  `2002:c000:0205::` walk past an exclusion of `192.0.2.5` when an IPv6 allow covers them.
- **Trailing-dot FQDN.** `printer.corp.example.` is not excluded by `printer.corp.example`.

**No scan-point-side conformance test exists** over `scopetest.Cases`, although
`internal/dispatch/scope_conformance_test.go:12` and `internal/dispatch/scope.go:87` both
say one does. Only Core is tested against the shared table.

**How to apply:** on any `internal/scanpoint` or `internal/enginewire` diff, re-run the
terminal-path race probes first — they are cheap and they are the family everything else in
this file hangs off. Separate "wrong now" from "wrong the moment a real engine lands":
`cvap-engine-noop` sends nothing, so today the orphan is a sleeping process and a false
CANCELLED record, and the day a real engine ships it is an unstoppable scanner.

Related: [[dispatch-scope-and-kill-gaps]], [[bypass-engine-import-guard]]
