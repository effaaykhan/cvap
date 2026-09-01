# ADR-030: Knowledge tables are read-only to the application role

**Status:** Accepted
**Date:** 2026-09-01

## Context

The seven knowledge tables — `rule_packs`, `rules`, `vulnerability_defs`, `rule_vuln_map`,
`vendor_advisories`, `advisory_vuln_map`, `advisory_fixed_packages` — are global and carry no
`tenant_id`, so RLS does not apply to them (ADR-017). They also hold detection content, which
decides what the product tells a customer is wrong with their estate. If the database role
that serves tenant API traffic can also write to them, then any SQL injection, deserialization
flaw or authorization bug in the application becomes a path to injecting or altering detection
logic — and a rule is a much more valuable thing to control than a row of one tenant's data.
ADR-019 already requires knowledge data to be signed and verified at import; that requirement
means nothing if the verifying step can be bypassed by writing to the table directly.

## Decision

`cvap_app` holds `SELECT` and nothing else on all seven knowledge tables. Granted in migration
0010, per-table, as `GRANT SELECT` — never `ALL`.

Writes belong to a **separate database identity** that only the signed-import path uses. That
role does not exist yet and is deliberately not created speculatively: it lands in the
migration that lands the rule-pack importer, alongside the code that verifies the signature
before it writes. Until then, knowledge content is loaded by the migration role.

This is the one place in the schema where a privilege boundary does work that RLS cannot.
Everywhere else, tenant isolation is the property being defended and RLS is the mechanism.
Here there is no tenant to isolate, so the grant is the whole of the control.

## Alternatives considered

**Grant `cvap_app` full DML on the knowledge tables and rely on ADR-019's signature check in
code.** The obvious choice, and the one that will be proposed the first time the importer is
inconvenient. Rejected on the same reasoning ADR-002 uses for tenancy: our own code enforcing
our own invariant is the trust boundary that fails. A signature check is worth having *and*
the role is worth having, because they fail independently — a bug in the verifier does not
also hand out write access, and a compromised application role does not also produce a
correctly signed pack.

**Create the import role now, empty, so the grant exists when needed.** Tidy, and it avoids
the future migration. Rejected: a role with write access to detection content and no code
using it is an unattended credential. It should come into existence at the moment something
verifies signatures with it, not months earlier.

**Put knowledge data in a separate database with its own connection.** Stronger isolation
still, and it makes the boundary physical rather than a grant. Rejected for the MVP: findings
join to `rules` on the read path, so a second database means either cross-database joins or
caching the rule corpus in the application, and both cost more than the grant buys. Worth
revisiting only if knowledge ingestion and tenant serving develop genuinely different
operational profiles.

**Make the knowledge tables owned by a role the application cannot reach, and expose them
through views.** Equivalent protection with more moving parts, and it would put `SELECT *`-
shaped views in front of tables the finding read path joins to. The grant achieves the same
thing with nothing to keep in sync.

## Consequences

An application-layer defect cannot become injected detection content, and the signed-import
path is the only way rules enter the system — which is what makes ADR-019's signature
requirement enforceable rather than aspirational.

The cost is real and lands on a specific future task: **the rule-pack importer cannot use
`cvap_app`, and will fail with a permission error the first time it runs.** That is intended.
The fix is a distinct role created in the importer's own migration, granted `INSERT`/`UPDATE`
on the knowledge tables and nothing else, with the same `NOBYPASSRLS`/`NOSUPERUSER` assertion
migration 0001 applies to `cvap_app`. The fix is **not** widening this grant, and this ADR
exists to make that widening a visible reversal of a recorded decision rather than a one-line
diff nobody reviews — because under schedule pressure, adding `INSERT` to an existing `GRANT`
is the path of least resistance and looks like a typo fix.

A second consequence worth naming: the knowledge tables now have a different write path from
every other table in the schema, so "how does data get into this table" has two answers
depending on which table you are looking at. That asymmetry is deliberate but it is a thing to
know.

## Review trigger

**When the rule-pack importer is built** — that is the moment this decision has to be honoured
with a new role rather than argued with. Revisit sooner if a legitimate Core code path needs
to write knowledge data outside the import flow, which would mean the boundary is drawn in the
wrong place rather than that it should be removed.
