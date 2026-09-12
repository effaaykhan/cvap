---
name: probing-the-store-and-advisory-paths
description: How to measure store/correlate changes — and the fact that make store-test silently skips every advisory-keyspace suite unless the import role URL is exported
metadata:
  type: project
---

`make store-test` exports `KNOWLEDGE_IMPORT_DATABASE_URL` from the environment only. If
it is unset (the common case), every suite calling `seedReleaseKeyspace` **skips
silently** — including the whole advisory-finding acceptance path. A green
`make store-test` is not evidence the advisory matcher ran.

Export both to make an advisory-path probe actually execute:

- `CVAP_TEST_DATABASE_URL` = `APP_DATABASE_URL` (role `cvap_app_login`)
- `KNOWLEDGE_IMPORT_DATABASE_URL` (role `cvap_knowledge_import_login`) — see `env.example`

**Why:** during the ADR-095 review (2026-09-12) the divergence between the stored release
and the release the matcher keyed on was only visible once the keyspace suites ran; with
the default invocation they skipped and the run still said `ok`. Same family as the
user's [[test-that-proves-nothing]] and [[gate-before-push]].

**How to apply:** seed probe advisories under a `PROBE-` prefix and a `CVE-2099-*` id so
they are distinguishable from the dev DB's real USN keyspace, assert on a CVE that exists
for exactly one release (that pins *which* release the matcher used), and **delete the
rows afterwards** — `vendor_advisories`/`advisory_fixed_packages`/`advisory_vuln_map`/
`vulnerability_defs` are global, unscoped by RLS, and shared with every other suite on
that database. For write-ordering races, two `db.Write` goroutines with a channel held
inside the first callback reproduces a cross-transaction interleaving reliably.
