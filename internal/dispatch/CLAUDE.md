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
