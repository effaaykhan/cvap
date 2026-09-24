# ADR-104: A seen-only port needs a migration after all

**Status:** Accepted
**Date:** 2026-09-24
**Supersedes:** ADR-103's claim that promoting discovery ports needs no migration. Every other
decision in ADR-103 stands — decision 1's shape, decision 2 (the rules do not see these rows), and
decision 3 — and this ADR changes only what it costs to build decision 1.

## Context

ADR-103 said: *"No migration: on `services` only `port` and `protocol` are `NOT NULL`."* That was
checked against the nullability of the columns and against nothing else. `services` also carries six
CHECK constraints, and one of them whitelists the column the decision depends on:

```
services_identification_method_known
  CHECK (identification_method IS NULL
         OR identification_method = ANY (ARRAY['banner','probe','tls-probe','ssh-kex','tls','none']))
```

`'discovery'` is not a member, so the write ADR-103 specifies is refused by the database:

```
ERROR: new row for relation "services" violates check constraint
       "services_identification_method_known"
```

The consequence is larger than a rejected row, and was measured before it was reasoned about.
`deriveServices` runs INSIDE `resolveHost`'s transaction, so the violation propagates and rolls the
whole host resolution back. A probe with one port observation added to an otherwise identical
fixture:

```
ANCHOR ONLY   -> assets=1
ANCHOR + PORT -> assets=0
```

One unwritable service row costs the entire asset. That atomicity is ADR-006's design working as
intended — resolveHost is one decision, and a partial host is the state it exists to prevent — but
it means a constraint violation on a service is not a missing service, it is a missing host.

## Decision

Extend `services_identification_method_known` to admit `'discovery'`, in a numbered migration.

The value stays distinct from `'none'`, and that distinction is the whole reason this is a
migration rather than a one-character change. `'none'` means *a probe ran and identified nothing*;
`'discovery'` means *nothing probed it, the port merely answered*. They are different strengths of
evidence about the same endpoint, and a reader deciding whether to trust a row — or a later change
deciding whether it is worth fingerprinting — needs to tell them apart.

## Alternatives considered

**Reuse `'none'`.** No migration, and rejected: it collapses "probed, unidentified" into "never
probed". The schema currently draws that line and this would erase it to save a file.

**Leave `identification_method` NULL.** Permitted by the CHECK and needs no migration, but it
replaces a positive marker with an absence, so every reader has to infer seen-only from
`product IS NULL AND identification_method IS NULL` — a predicate that will drift out of agreement
across the API, the UI and any future rule.

**Catch the violation in `deriveServices` and continue.** Rejected outright: it would convert a
schema error into silence, and the row would go missing with nothing saying so.

## Consequences

One more migration, with the review that implies (`schema-auditor`, `rls-test`). No RLS or grant
change — `services` already carries both, and this alters a CHECK only.

And a caution worth leaving where the next person will find it: **a failed service write loses the
host, not just the service.** Any future change that adds a constraint to `services`, or writes a
new kind of row into it, is changing the failure mode of host resolution. That was not obvious from
reading `deriveServices`, and it cost this change a full debugging cycle to find.

## Review trigger

If a third kind of unidentified evidence appears — a UDP port that answers but cannot be read, an
ARP-only host — and the whitelist starts growing one value per evidence kind, the constraint has
become a taxonomy and belongs in its own table or as a separate provenance column.
