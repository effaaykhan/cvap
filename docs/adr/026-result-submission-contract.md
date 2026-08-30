# ADR-026: Result submission contract

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 did not address result submission at all, and it is the part that fails first at real
volume. A credentialed inventory of a large Windows server is megabytes; a /16 discovery
result is larger. Scan Points submit across networks we do not control, from inside
environments where Core may be unreachable for hours, over connections that drop mid-upload.
Naive submission loses results, duplicates them, or OOMs a scan point inside a customer's
network.

## Decision

Result submission is a distinct contract from job dispatch, carried by its own **Ingest
service** rather than folded into the dispatch stream.

- **Idempotency.** Every submission carries a `submission_id`. A Scan Point that submits and
  loses the connection before the ack will retry; ingest deduplicates on that ID.
- **Chunked upload with resumption.** Large results upload in chunks and resume from the last
  acknowledged chunk rather than restarting.
- **Per-chunk acknowledgement.** `SubmitResults` is bidirectionally streaming
  (`stream ResultChunk` → `stream SubmitAck`). A terminal-only ack cannot express a resumption
  point, and a saturation signal that arrives after the upload finishes has applied no
  backpressure to it.
- **Backpressure in both directions.** Explicit protocol-level flow control:
  scan-point-initiated when its local buffer grows, Core-initiated via `SubmitAck.retry_after_ms`
  while the upload is still running. Scan Points slow down; they never queue unboundedly.
- **Local durability, not discard.** A Scan Point that completes work and cannot reach Core
  persists results to local **encrypted** storage and retries.
- **Five submission outcomes**, because two are not enough to tell a scan point what to do
  with its buffer:

  | `SubmitAck.status` | Meaning | Scan point does |
  |---|---|---|
  | `ACCEPTED` | Processed normally | Clear buffer |
  | `ACCEPTED_QUARANTINED` | Stored, withheld from the finding pipeline, operator-surfaced | Stop retrying, clear buffer |
  | `REJECTED_DUPLICATE` | `submission_id` already ingested | Clear buffer, no retry |
  | `REJECTED_MALFORMED` | Unparseable, or unknown `observation_type` | Clear buffer, no retry, log locally |
  | `RETRY_LATER` | Transient Core-side failure | Keep buffer, back off |

- **Epoch check at ingest.** A superseded lease epoch yields `ACCEPTED_QUARANTINED` — stored
  and escalated, never discarded (ADR-012). `RETRY_LATER` as a distinct status is what stops a
  scan point retrying forever against a malformed payload, or deleting its buffer during a
  transient Core outage.

**Results are always persisted and submitted. Nothing is discarded.** Architecture-v2 leaves
this open — §11's `ABORT` node says "discard partial active work" while §16 says buffer locally
and retry. **§16 wins outright**, and §11's `ABORT` node is corrected to *zeroise credentials,
mark results incomplete, submit*.

`reassign_safe` governs **retry, not retention**. The two are independent:

- Observations from a job that lost its lease are submitted with `incomplete = true`. Core
  stores them **unconditionally**, whatever the job's `reassign_safe` value.
- Core does **not** run the finding pipeline over incomplete results from a
  non-`reassign_safe` job. The record is kept for the operator, not converted into findings.
- For a `reassign_safe` job the retry supersedes the incomplete attempt, and dedup (ADR-010)
  absorbs the overlap.

The stored incomplete record is the answer to "what did we touch", which is precisely what an
operator needs after an intrusive job died mid-flight — the case where ADR-012 escalates to a
human rather than retrying.

## Alternatives considered

**Fold submission into the dispatch stream.** One connection, one protocol, and it is the
obvious simplification once ADR-005's bidirectional stream exists. Rejected: it couples upload
progress to dispatch liveness, so a long chunked upload blocks or is killed by a dispatch
reconnect, and it makes independent scaling of ingest impossible. Ingest and dispatch have
genuinely different load shapes.

**A single terminal `SubmitAck`, with a separate status RPC for resumption.** Simpler
cardinality, and it was the original sketch. Rejected: polling for a resumption point is a
workaround for a streaming shape we can still choose correctly, and changing an RPC's streaming
cardinality later is a major-version break under ADR-022 rather than an additive change. This
is a decide-now item, not a fix-later one.

**At-least-once submission with dedup at the finding pipeline instead of at ingest.**
Rejected: the dedup key (ADR-010) is computed downstream of correlation, so duplicate
observations would already have been written and merged into assets before anything noticed.
Idempotency has to be at the boundary.

**Unbounded client-side queueing with no backpressure.** Simplest for Core. Rejected: it moves
the failure into the customer's network, where a scan point OOMs or fills a disk we cannot
see and cannot debug. Explicit flow control makes saturation a slowdown rather than an outage.

**Discard results when Core is unreachable.** Rejected: a scan point that finishes a two-hour
credentialed job and throws the results away has spent the customer's maintenance window for
nothing, and the failure is invisible until someone notices missing data.

**Discard partial results from a job that lost its lease.** Superficially safe — the partials
are incomplete, and for a non-`reassign_safe` job nothing will supersede them. Rejected on the
operational case: an intrusive job that died mid-flight has already put packets on the wire,
and the partial record is the only account of what was touched. Discarding it destroys exactly
the evidence the operator escalation in ADR-012 exists to serve. Flagging `incomplete` and
withholding the results from the finding pipeline gets the safety without the amnesia.

**Plain durability with no encryption at rest.** Rejected: buffered results are exactly the
inventory-and-weakness data the threat model says a hostile network must not yield (§18.3).
The buffer is bounded and transient, but it is not public.

## Consequences

Results survive connection loss, Core restarts and multi-hour outages, and the system degrades
by slowing rather than by dropping data. Every job leaves a record of what it touched, whether
or not it finished — which is what makes ADR-012's fail-loudly escalation actionable instead
of merely loud. Ingest can scale independently of dispatch. The costs: a `submission_id` and
chunk-offset state machine on both sides that must be tested against partial failure, not just
happy paths; encrypted local storage on the scan point with a key management story of its own;
an `incomplete` flag that the finding pipeline must honour, since storing results the pipeline
must not process is a rule enforced in code rather than by the schema; and a real operational
case where a scan point returns after a long outage to find its epoch superseded (ADR-012),
whose results are stored as `ACCEPTED_QUARANTINED` and surface to an operator rather than
vanish. Because ADR-022 makes the wire format
additive-only, `submission_id`, chunk framing and the backpressure signal are effectively
frozen once shipped.

## Review trigger

Revisit if measured ingest throughput becomes the binding constraint on scan concurrency, or
if the rate of buffered-then-rejected results after scan point outages is high enough that
the epoch window needs rethinking rather than the submission path.
