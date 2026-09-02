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
