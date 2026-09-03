# internal/scanpoint

Scan point runtime: connection, lease client, engine host, result buffering.

Rules:

- Outbound only. This package never listens.
- Never imports `internal/control` or `internal/store`.
- Emits observations. Never constructs an Asset or Finding.
- Lease renewal failure means self-abort and credential zeroise, on every path including
  panic recovery. Not "log and continue".
- Credentials live in memory for the life of the job and nowhere else.
- **A hand-written type holding credential material stores it in a `func() string` field and
  implements `String()`, `GoString()`, `LogValue()` and `MarshalJSON()` returning a redacted
  form (ADR-035).** This reverses what this file said before that ADR: the old rule was that
  such a type must NOT implement `String` or `MarshalJSON`, which is exactly backwards.
  Implementing nothing is not safe — a bare struct with an unexported string field still
  prints its contents under `%v`. And the methods alone are not sufficient either: `fmt`
  calls none of them when the value sits in an unexported field of another struct, because
  `reflect.Value.CanInterface` is false there. The func field is what closes that; the
  methods make the output legible. `Reveal()` is the only accessor.
- The generated protobuf types do have `String()` and cannot be changed: log them only
  through `logging.Proto` / `logging.ProtoAttr`, which `make secret-logging` enforces. No
  interceptor, middleware or tracing layer may render message bodies (ADR-034).
- **Credentials stop here.** Engine processes never receive raw credential material: the
  runtime holds the credential, establishes the authenticated session, and passes the engine
  a session handle or a short-lived derived token (ADR-020, ADR-027).
- **The runtime is the scan-point-side enforcement site, not the engine.** It applies the
  job's `ScanConstraints` on the send path — allowlist, exclusions, rate, concurrency,
  timeouts, the `fragile` cap — and it authorises any target an engine discovers mid-scan
  before that engine may touch it. Engines receive resolved targets and construct none
  (ADR-024, ADR-027).
- The runtime owns the rate budget and allocates slices to engine processes, never
  allocating more in aggregate than the platform ceiling. Engines report actual send counts;
  the runtime reclaims unused allocation. There is no shared mutable rate state between
  processes.
- Engine supervision is the runtime's job: restart policy, zombie reaping, and `SIGTERM`
  then `SIGKILL` on kill-switch propagation, comfortably inside the 10-second bound.
- **Results are always submitted, never discarded** (ADR-026). On lease loss: zeroise
  credentials, mark the results `incomplete` with a `termination_reason`, and submit them.
  The record of what was touched is what an operator needs after an intrusive job died
  mid-flight.
- Results buffer to local encrypted storage when Core is unreachable, and resume from the
  last acknowledged chunk. Clear the buffer only on `ACCEPTED`, `ACCEPTED_QUARANTINED`,
  `REJECTED_DUPLICATE` or `REJECTED_MALFORMED` — never on `RETRY_LATER`.

This package concentrates scope, rate and credential enforcement in one component, which
makes it the one whose correctness carries the most. Run `scan-safety-auditor` on any
change here.

## What exists, and the shape of it

`Runtime` owns a job table keyed by `job_id`. That table is what makes reconnect safe.

**Reconnect carries no new wire message, because renewal already IS the reconciliation.** On a
fresh stream the runtime renews every job it holds and Core answers from
`job_leases.holder_scan_point`, which survives the disconnect: `GRANTED` means carry on, `LOST`
or `UNKNOWN_JOB` means self-abort. An assignment for a `job_id` already in the table is never
started twice — the same epoch is a duplicate delivery and is ignored, a higher epoch means the
held incarnation lost its lease and is aborted before the new one starts, a lower epoch is a
stale message and is ignored. Jobs are **not** cancelled when the stream drops: a network blip
is not lease loss, and the lease clock decides rather than the socket.

**Self-abort is a timer, not an event.** The failure that matters is the one where nothing
arrives — the stream is down, so no `LeaseGrant` will ever say `LOST`. `watchLeases` compares
the clock against each job's expiry minus `LeaseSafetyMargin` and aborts on its own. The margin
is not decoration: Core may reassign the instant its own clock passes the expiry, so a runtime
scanning until the same instant would still be sending packets while a second scan point had
started the same work.

**The abort ORDER is load-bearing**: stop the engine (SIGTERM, then SIGKILL after the grace),
**zeroise**, then submit. Zeroisation comes before submission because an upload against an
unreachable Core can block for a long time, and credential lifetime must not be tied to how
long an upload takes. `sync.Once` guards the whole terminal path, because lease loss, a
`CancelJob` and a kill switch race by construction.

**An engine that dies on its own is `ENGINE_FAILURE`** — a third outcome, not folded into lease
loss or completion — and the engine is **not restarted**. A crashed engine restarted under the
same lease is duplicate execution against the same targets; whether the work re-runs is Core's
decision through `reassign_safe`, not this runtime's. An exit 0 without the `done` message
counts as failure too: reporting a partial scan as a whole one is under-scanning that looks
like a clean run, which is the worst failure this system has.

**Targets arrive CANONICAL, and the runtime re-computes rather than validating** (ADR-044,
superseding ADR-042).
`target.Matches` canonicalises the received string with the same function Core ran at planning
and requires the result to equal what arrived, **byte for byte, with no trimming before the
comparison**. Asking instead "is this string canonical" would accept a canonical form of the
WRONG host — which is what a bug in Core's canonicalisation produces — so the comparison is what
makes this an independent computation whose answer may disagree, rather than a check of Core's
homework. A mismatch refuses the job the same way an out-of-scope target does —
`SCOPE_VIOLATION_HALT`, because the wire enum is frozen and a new reason is a proto change —
but the error text says which of the two it was. That distinction matters to whoever reads it:
a scope violation means policy and plan disagree, while a canonicalisation mismatch means
something between Core and this scan point changed the string.

**Scope is enforced here, once, through `internal/scope`** — the same matcher Core uses, so the
two sites cannot disagree about a rule. Since ADR-044 that matcher is narrower: it compares one
canonical string per host against operator-written rules and no longer parses ports, brackets,
URLs or notation at all. Targets are checked before they reach the engine's
stdin, and a target an engine discovers mid-scan comes back as an `authorise` request answered
here. A target Core assigned that fails this check **refuses the whole job** with
`SCOPE_VIOLATION_HALT` rather than being trimmed: a disagreement between the two enforcement
sites is the most important thing an operator could be told. `internal/scope/scopetest` holds
the case table both sites are tested against.

**Credentials** live in `Credential`, whose material sits behind two func fields and no byte
field — ADR-038, superseding ADR-035's `func() string`, because a Go string cannot be zeroised
at all. `creds_test.go` repeats the verb enumeration in every position including an unexported
field, which is the one place no method of ours can run.

**The buffer is bounded and refuses work at the bound.** ADR-026's encrypted local durability is
**not implemented** — deferred in `docs/execution-plan.md` §6.5 with what unblocks it, because
the only key custody available on a scan point today is a key file beside its ciphertext. A
full buffer reports `BACKPRESSURE_STATE_HARD` and refuses assignments rather than dropping
observations, which is the failure ADR-026 exists to prevent.
