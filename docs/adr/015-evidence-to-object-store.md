# ADR-015: Large evidence to object store; summary in Postgres

**Status:** Accepted
**Date:** 2026-08-30

## Context

Evidence-based detection at Core (ADR-013) means Scan Points ship what they saw, and some of
what they saw is large: full HTTP transactions, packet captures, screenshots, credentialed
inventories of large Windows servers, and generated reports. These do not belong in the
transactional database that also serves dashboards.

## Decision

Large evidence goes to an S3-compatible object store. `EVIDENCE.data` holds a summary
sufficient for display and correlation; `EVIDENCE.object_store_ref` holds the pointer to the
full artefact. Reports are stored the same way, via `REPORT.object_store_ref`. S3-compatible
means MinIO covers the on-prem and air-gapped deployments without a second code path.

**Evidence follows the lifetime of its finding, not the observation retention clock**
(ADR-016): evidence on an open finding is retained as long as the finding; evidence on a
closed finding — object-store artefact included — drops 90 days after closure. The row and the
artefact expire together; neither is removed without the other.

Because evidence is pruned by finding status rather than by time, **`EVIDENCE` is not
partitioned** (ADR-016). Its content is *copied* from the observation at finding creation
rather than referenced, so `EVIDENCE.observation_id` is a nullable soft reference for
provenance that goes null once the observation ages out.

## Alternatives considered

**Everything in Postgres as `bytea` or large `jsonb`.** One store, one backup, one
transaction — genuinely simpler, and the reason this needs stating. Rejected because it puts
multi-megabyte blobs in the same tables that serve interactive queries, inflates backup and
replication cost by orders of magnitude, and makes retention pruning (ADR-016) a vacuum
problem rather than a delete.

**A filesystem path on the Core host.** Cheapest for single-node Compose. Rejected because it
does not survive the multi-node and SaaS deployments in ADR-023, and it makes the storage
layer a deployment-mode-specific code path.

**Store only the summary and discard the full artefact.** Rejected: the full transaction is
what makes a DAST or credentialed finding defensible when an application team disputes it,
and re-running correlation over history (ADR-006) may need evidence the original summary did
not anticipate.

**A cloud-vendor-specific store (S3 proper, GCS).** Rejected: on-prem and air-gapped
customers exist in this market, so the interface must be one MinIO satisfies.

## Consequences

Postgres stays sized for transactional work and its backups stay tractable. Every open
finding can be substantiated by the full artefact that proved it, for as long as it stays
open. The costs are a second store to deploy, secure, back up and provide credentials for in
every deployment mode; a referential integrity gap Postgres cannot enforce, so orphaned refs
and orphaned objects are both possible and need a reconciliation path — and since that same
sweep is what expires closed findings' artefacts, it is required rather than optional; and an
extra fetch on the finding detail view.

## Review trigger

Revisit if the reconciliation burden between Postgres refs and object store contents proves
worse than the storage saving, or if a deployment target appears with no viable
S3-compatible option.
