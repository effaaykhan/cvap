# ADR-029: Schema tables the v2 ERD does not draw

**Status:** Accepted
**Date:** 2026-09-01

## Context

The v2 ERD (architecture-v2 §9) was drawn in August. ADR-007 and ADR-026 were accepted
afterwards and each requires persistent state the diagram has no entity for, and the ERD
draws one many-to-many relationship without the join table that implements it. Generating
migrations straight from the ERD, as execution-plan §4.3 instructs, therefore produces a
schema that cannot satisfy two accepted ADRs — and the omission looks like an oversight in
the migration rather than a gap in the diagram.

## Decision

Six tables exist in the schema that the ERD does not draw. Each is listed here with the
decision that requires it, so a future reader diffing schema against diagram finds the
reason rather than a discrepancy. Four are required by ADRs accepted after the diagram; two
are join tables the diagram implies but cannot name.

- **`result_submissions`** — ADR-026's idempotency ledger. Ingest deduplicates on
  `submission_id`, so the ID needs a row to be deduplicated against; without it
  `observations.submission_id` references nothing and at-least-once submission silently
  becomes at-least-twice ingestion. It also holds the per-submission facts ADR-026 defines:
  `lease_epoch`, the `SubmitStatus` outcome, chunk resumption state, `incomplete`,
  `termination_reason` and `quarantine_reason`. Created before `observations`, which
  references it.
- **`asset_resolution_queue`** — ADR-007's unresolved queue. Conflicting or insufficient
  identity evidence must reach an operator rather than be guessed, which needs somewhere to
  hold the candidate asset IDs and the conflicting evidence until someone adjudicates. It is
  a table and not a column on `observations`: observations are immutable and ephemeral
  (ADR-016), and an adjudication that outlives the 90-day window is exactly the load-bearing
  state that rule says to copy.
- **`enrollment_tokens`** — ADR-018's single-use, TTL-bounded enrolment credential, added in
  migration 0017. The ERD draws no way for a scan point to acquire an identity at all: it
  shows `SCAN_POINT.cert_fingerprint` as though the certificate simply exists. This table is
  where the tenant and the zone come from, and the zone above all — a scan point must not be
  able to influence its own vantage point (ADR-008), so `EnrollRequest` carries no zone field
  and this row is the only source of one.
- **`scan_point_certificates`** — issuance history, added in migration 0018.
  `SCAN_POINT.cert_fingerprint` answers "who is this peer, now", and replacing it in place is
  what makes revocation immediate (ADR-031) — and also what destroys the record of which
  certificate was valid when. Backfilled at creation so the history has no hole covering
  everything before the migration.
- **`scan_policy_credential_profiles`** and **`advisory_vuln_map`** — join tables for the
  ERD's own `SCAN_POLICY }o--o{ CREDENTIAL_PROFILE` and
  `VULNERABILITY_DEF }o--o{ VENDOR_ADVISORY`. Mermaid draws a many-to-many as a line; a
  relational schema needs the table. Listed here because they are tables the diagram does
  not name, not because a later ADR introduced them. Both many-to-many relationships are
  load-bearing: ADR-009 rejects a one-to-one rule-to-CVE mapping in both directions, and one
  advisory commonly fixes several CVEs while one CVE is commonly addressed by an advisory
  per distro release.

`quarantine_reason` lives on `result_submissions`, written once per submission. Observations
carry `ingest_state` — what the finding pipeline filters on — but not the reason, which would
otherwise be duplicated across every row of a chunk stream on the largest table in the system.

## Alternatives considered

**Give each table its own ADR as it is discovered.** Rejected: the decision is one decision
— "the diagram is annotated, not redrawn" — and splitting it across records makes the
complete list of divergences something you have to assemble rather than read.

**Redraw the ERD and skip the ADR.** Rejected on the precedent §9.1 already set: that section
records ADR-016's supersession as an annotation and leaves the diagram alone. The diagram is
a record of what was decided in August, and rewriting it destroys the ability to see that a
decision changed. An annotation pointing at an ADR keeps both the original and the correction.

**Derive the unresolved queue from `observations` where `asset_id IS NULL`.** Attractive
because it adds no table. Rejected: it conflates "not yet resolved" with "resolution failed
and needs a human", carries no candidate set and no adjudication state, and the row it depends
on drops after 90 days — so an unworked queue item silently disappears rather than ageing
into someone's backlog.

**Fold submission state into `scan_jobs`.** One fewer table, and a job is the natural owner.
Rejected: a job produces many submissions across chunked, resumed and retried uploads, so the
cardinality is wrong, and the idempotency check would then contend on the job row on the
ingest hot path.

**Put `quarantine_reason` on `observations` alongside `ingest_state`.** Rejected: the reason
is a property of the submission, identical for every observation in it, on the table ADR-016
identifies as the growth vector. Duplicating it per row to avoid a join is the wrong trade in
the one place where row width matters most.

**Leave all three to a later migration once the services are built.** Rejected for
`result_submissions` specifically: `observations` references it, and a table that an earlier
migration depends on cannot be added by a later one without rewriting the earlier.

## Consequences

The schema satisfies ADR-007 and ADR-026 rather than only the ERD, and the divergence is
documented where the next person to compare them will look. The cost is a diagram that is now
incomplete in six named places, which is a maintenance obligation: a seventh table that the
ERD lacks belongs in this ADR, not in a further one. That obligation has now been exercised
three times — `advisory_vuln_map` while writing migration 0010, and both enrolment tables
while building the Enrollment service — which is evidence the annotation approach is holding
rather than that it is failing. The signal to redraw is when a reader can no longer hold the
divergences in mind, not the count itself. Anyone regenerating the schema from the
diagram alone will still produce the wrong thing, so execution-plan §4.3's "generate
migrations directly from the v2 ERD" is now qualified by this record.

## Review trigger

Revisit when the ERD is next redrawn in full — at which point these three should be absorbed
into it and this ADR marked superseded — or when a fourth ADR-required table has no home in
the diagram, which is the signal that the annotation approach has stopped scaling.
