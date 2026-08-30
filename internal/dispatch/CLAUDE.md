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
  never lets them queue unboundedly inside a customer's network.
