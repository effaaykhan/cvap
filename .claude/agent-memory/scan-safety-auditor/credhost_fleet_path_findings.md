---
name: credhost-fleet-path-findings
description: ADR-091 credentialed-host dispatch audit (2026-09-11) — host engine missing from planner dialsTargets (hostname scope bypass), pooled host-key trust, agent ServeAgent nil-panic, no rate/fragile model
metadata:
  type: project
---

Measured against the uncommitted ADR-091 working tree (session 41+, 2026-09-11). Check these
first on any change to `internal/engines/credhost`, `internal/dispatch/credgrant.go` or the
credentialed runtime path.

**`store.EngineHost` is missing from `dialsTargets` (`internal/dispatch/planner.go:206`).**
That map is the repair for the discovery hostname bypass: `expandFor` refuses a hostname task
for any engine that dials. credhost dials (`credscan.ReadHost` → `net.JoinHostPort(t.Value,22)`),
so planning accepts a hostname task for it. Measured: `expandFor("host","ssh1.corp.example")`
returns the name with no error while discovery/fingerprint refuse it; a hostname allow rule +
an operator-pinned `known_hosts` gets a credentialed assignment onto the wire, both enforcement
sites permit the name, and the engine resolves it itself at dial time. The map's own comment
("the cost of being wrong in that direction is a refused hostname rather than a scope bypass")
is wrong in this direction: omitting a dialing engine IS the bypass. See [[latent-limitations]]
and [[credscan-hostname-dial-gap]] — third recurrence of the same class.

**Operator-pinned `known_hosts` short-circuits every per-task trust check.**
`trustMaterial` returns `profile.KnownHosts` verbatim whenever it is non-empty; the
`netip.ParseAddr(t.TaskTarget)` refusal and the observed-fingerprint lookup only guard the
OBSERVED branch. Measured: a pin naming `10.0.0.1` dispatches a job whose only target is
`192.0.2.7`, with `credential.granted` and no refusal. ADR-091 §4's "no pin covers it" refusal
is not implemented.

**`credhost.hostKeyCallback` binds no material to a host.** It ignores the host field of each
line and both of its own (hostname, net.Addr) arguments, so every line in the job's known_hosts
verifies every target in the job. Measured both ways (observed fingerprint of .7 accepted for
.4; operator pin for 10.0.0.1 accepted for 203.0.113.9). This is what turns the hostname bypass
into an actual login rather than a failed handshake.

**`CredAgent.EngineFile` panics the scan point if Zeroise wins the race**
(`internal/scanpoint/credagent.go:107`): the `go agent.ServeAgent(a.keyring, a.runtime)`
goroutine reads both fields with no lock, and `Zeroise` nils them. Reproduced from the
production `runJob` path (2 of 3 runs) with a credentialed host job whose target the runtime
refuses — agent built, `start()` returns `ErrOutOfScope`, deferred zeroise, nil conn, SIGSEGV.
An unrecovered goroutine panic takes the whole scan point down, losing every other job's
results and attestations.

**Runtime order is credential-then-scope, the reverse of Core's.** `runJob` calls
`awaitCredential` (up to `CredentialGrantWait` = 30 s, builds the agent) before
`host.start`'s `authorise`. Measured: `agents built = 1` on a job that terminates
SCOPE_VIOLATION_HALT; and with no grant the scope disagreement is reported as ENGINE_FAILURE
"no credential grant arrived" 30 s later, so site-two disagreement is masked.

**credhost is outside the packet-budget model.** No reference to `RatePPS`,
`MaxConcurrentPerTarget` or `enginerate` anywhere in the engine; only `ConnectTimeoutMS` is
honoured, and only for connect/handshake — `cmd/cvap-engine-credhost/main.go` passes
`context.Background()`, so the command phase has no deadline (the instrument passes
`timeout+30s`). `fragile` therefore caps nothing on this path. `make safety` does not drive
this engine.

Order that IS correct and measured, do not re-audit: `offerWork` runs the scope loop before
`credentialedAssignment` (out-of-scope host job → resolver calls 0, grant rows 0, status failed,
`job.scope_refused`); the harness mutation `agents[:0]` kills three tests; cancel with the
maximum grace closes the agent socket at 9.01 s, inside ADR-024's 10 s.

**Status (same day, before commit):** every finding above was fixed in the ADR-091 commit and
is pinned by a test — `dialsTargets` lists `store.EngineHost` (`TestHostnameIsRefusedForTheCredentialedHostEngine`);
`hostKeyCallback` binds trust per host (`TestHostKeyCallbackBindsTrustToTheHost`) and Core composes
per-task pin lines (`hostkeytrust.LinesCovering`); the `ServeAgent` goroutine takes its own
references (`TestAgentZeroiseRacingItsOwnServeGoroutineDoesNotPanic`); the socketpair is
`SOCK_CLOEXEC` (`TestAgentSocketIsCloseOnExec`); the runtime authorises before `awaitCredential`;
the engine read is bounded. Still open and recorded as gaps in ADR-091: credhost outside the
rate/fragile model; `zeroised_at` set over an empty list after a Core-side drop. Re-measure rather
than re-report: the fixes are what to probe next time.
