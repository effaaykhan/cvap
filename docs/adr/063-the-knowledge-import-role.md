# ADR-063: The knowledge-import role is scoped to exactly the knowledge tables

**Status:** Accepted
**Date:** 2026-09-08

## Context

ADR-030 settled that `cvap_app` — the role that serves tenant API traffic — holds `SELECT`
and nothing else on the knowledge tables, because a role that can both serve requests and
write detection content turns any injection or authorization bug into a path to altering what
the product tells a customer is wrong with their estate. It also said the write identity
"does not exist yet and is deliberately not created speculatively: it lands in the migration
that lands the [advisory] importer, alongside the code that verifies … before it writes."

Phase 3.2 lands that importer (`knowledge/usn_ingest.py`, ADR-014). So the role lands now, and
this ADR records what it is and — the part worth writing down — what it must **not** be.

ADR-030 is the argument stated from `cvap_app`'s side: the serving role must not write. This
is the same argument from the *other* side: the writing role is the one thing in the system
whose whole job is to change detection content, so it is the highest-value identity to
compromise, and it must therefore be the narrowest.

## Decision

The write identity is `cvap_knowledge_import` (migration 0034):

- **`NOLOGIN`.** It is a group role holding grants, with no password to leak or rotate —
  exactly `cvap_app`'s shape. A `LOGIN` member (`cvap_knowledge_import_login`, provisioned by
  `app_role.sql` in dev/CI and by provisioning elsewhere) is what the importer connects as.
- **`NOBYPASSRLS` and `NOSUPERUSER`, asserted in the migration.** Migration 0001 makes this
  assertion for `cvap_app` and fails the deploy if it is false; 0034 repeats it for this role.
  The injection guarantee depends on the role being unable to reach past its grants, and a
  `DATABASE_URL` edited to a superuser "to fix a permission error" is exactly how that
  guarantee is quietly lost.
- **`GRANT SELECT, INSERT, UPDATE, DELETE` on exactly the five knowledge tables**
  (`vulnerability_defs`, `vendor_advisories`, `advisory_vuln_map`, `advisory_fixed_packages`,
  `knowledge_feed_status`) and nothing else. No blanket schema grant. Adding a sixth table to
  that list is a visible, reviewable widening — the way ADR-030 makes widening `cvap_app`'s
  grant one.

`cvap_app` additionally gains `SELECT` on the new `knowledge_feed_status` table, for the
freshness surface. It never writes it.

The signature/verification requirement of ADR-019 still stands and is **independent** of this
role, deliberately: a bug in the verifier must not also hand out write access, and a
compromised import role must not also be able to produce a correctly signed pack. Today the
USN pipeline's verification is provenance-on-import (feed, URL, fetched-at, ETag recorded on
every advisory) rather than a cryptographic signature; the signed-pack path is ADR-019's and
lands with the feeds that publish signatures. The role boundary holds regardless of which.

## Consequences

- The import path connects as a role that can do nothing outside the knowledge tables. An
  injection in the importer reaches advisories — bad, but bounded — and never tenant data,
  scan configuration, or credentials.
- `cvap_app` reading `knowledge_feed_status` from inside a tenant `Read` is the same
  global-table-read-inside-a-tenant-transaction case the store already relies on for `rules`
  (store `CLAUDE.md`); it needs no unscoped primitive.
- The `TestAppRoleCannotWriteKnowledge` integration test asserts the negative — `cvap_app` is
  refused an `INSERT` on `advisory_fixed_packages` — because a widened grant is invisible in
  review: the read path keeps working and only an injected advisory reveals the hole.
- **`knowledge_feed_status` is the FOURTEENTH table the v2 ERD does not draw**, and recording
  it here is deliberate: ADR-029 enumerates the thirteen undrawn tables and names its own
  review trigger as "a fourteenth arriving unrecorded." This is that fourteenth. It is a
  global, no-`tenant_id`, no-RLS knowledge table (ADR-030), correctly so; the gap it closes is
  documentary, not schematic. Per ADR-029's trigger the fourteenth is the signal that the
  per-table annotation has stopped scaling and the ERD should be redrawn in full with these
  absorbed — that redraw is out of this session's scope and is filed as a backlog item
  (**B27**). `internal/store/CLAUDE.md`'s undrawn-table list and its global-knowledge-table
  list are updated *from* this record, not independently, as that file requires.

## Alternatives considered

**Reuse the migration role for imports.** It already writes knowledge (ADR-030 says migration
loads it "until then"). Rejected: the migration role bypasses RLS and owns the schema, so an
importer running as it has the entire database as blast radius for the sake of writing five
tables. The importer runs on a schedule against a hostile feed (ADR-014) — precisely the code
that should hold the least privilege, not the most.

**One combined `cvap_app` grant plus the ADR-019 signature check.** This is ADR-030's rejected
alternative, and it is rejected here for the same reason: the two controls must fail
independently.
