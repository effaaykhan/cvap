# ADR-003: Job dispatch via Postgres SKIP LOCKED; broker deferred

**Status:** Accepted
**Date:** 2026-08-30

## Context

Jobs must be handed to Scan Points reliably, with transactional state transitions and
without a second source of truth. A scanning workload generates far fewer job dispatches per
second than a typical message-queue deployment is built for. Every additional infrastructure
component is one the customer must install, monitor and upgrade in their own environment.

## Decision

Job dispatch uses `SELECT ... FOR UPDATE SKIP LOCKED` against the job table in PostgreSQL.
Job state, lease state and dispatch are one transaction against one store. NATS JetStream is
introduced only when there is a measured throughput reason to do so, and the dispatch
service interface (ADR-004) is the seam that makes that substitution possible without
touching Scan Points.

## Alternatives considered

**NATS JetStream (or Kafka, or RabbitMQ) from the start.** Rejected for now, not forever.
It handles throughput we do not have, and in exchange it adds a component to every on-prem
install, splits job state across two systems that must be reconciled after a crash, and
makes the at-most-once guarantee ADR-012 needs for intrusive jobs harder rather than
easier, because the broker's redelivery semantics then have to be reconciled with the lease
epoch held in Postgres. The measured reason to adopt it does not exist yet.

**Redis as a work queue.** Already in the stack for cache and ephemeral coordination, so it
is tempting. Rejected because job state is not ephemeral: it must survive restart, be
auditable, and participate in the same transaction as the lease epoch. Redis persistence
guarantees are the wrong shape for that.

**Polling a plain status column without `SKIP LOCKED`.** Correct but serialising: concurrent
dispatchers block on the same rows. `SKIP LOCKED` is the standard mechanism for exactly this
and costs nothing extra.

## Consequences

One fewer component to install, monitor and support on-prem. Job state, leases and results
share a transaction boundary, which makes the epoch check in ADR-012 straightforward. The
cost is a dispatch ceiling bounded by Postgres write throughput and a polling loop rather
than a push notification, adding dispatch latency measured in the poll interval. We accept
both, and we accept that migrating to a broker later requires the ADR-004 seam to have held.

## Review trigger

Revisit when measured job dispatch rate or queue latency approaches the point where Postgres
contention is visible in production — not on the basis of projected scale, and not on
architectural preference.
