# ADR-062: The version comparators are validated against the distributions' own corpora and libraries, and Go is authoritative over SQL

**Status:** Accepted
**Date:** 2026-09-08

## Context

P3.1 (ADR-059, ADR-060) built the dpkg and rpm version comparators — Go, in
`internal/version`, because they run at match time in the finding pipeline and
ADR-014 forbids shelling out (Core must compare an RHEL version from a
Debian-based host). ADR-014's whole reason for existing is that a comparator bug
is a **silent false negative**: a vulnerable host reported clean generates no
complaint, no ticket, no signal. So the validation has to be stronger than "it
passes tests I wrote" — a comparator validated against tests derived from the same
understanding that produced it is validated against nothing.

## Decision

### 1. The corpora are the distributions' own, vendored with provenance

The test corpora are rpm's `tests/rpmvercmp.at` and dpkg's `scripts/t/Dpkg_Version.t`
`__DATA__` block — the projects' OWN suites, so a pass is agreement with rpm's and
dpkg's understanding, not a re-transcription of ours. Vendored under
`internal/version/testdata/corpora/{rpm,dpkg}/` (NOT a top-level `vendor/` — Go
reserves that for module dependencies and a stray one breaks the build), each with
a `PROVENANCE.md` recording the upstream repo, file path, commit SHA and fetch
date, and a refresh command. **A corpus with no provenance becomes indistinguishable
from one someone wrote**, and a parse that finds zero cases fails the test — a
corpus that silently stopped being read is worse than none (the §5.5 presence
lesson). Result at adoption: dpkg 43/43, rpm 103/103, zero failures.

### 2. The oracle differential is a real gate, not a one-off

Static vectors are a fixed list; the stronger validation is agreement with the
actual library. `oracle_test.go` compares our comparators against **dpkg's own
`--compare-versions` (libdpkg/libapt) and librpm** over the corpus pairs. Shape is
CVAP_REQUIRE_LAB's: if the tool is present it runs and **fails on any disagreement**;
if absent it **skips loudly, naming what did not run** ("agreement with librpm is
UNVERIFIED"); `CVAP_REQUIRE_VERCMP_ORACLE=1` turns the skip into a failure. **CI
installs dpkg and python3-rpm and sets the flag**, so the differential cannot
silently vanish. At adoption, run on this Ubuntu host: dpkg oracle 43/43 agree with
libdpkg; librpm skipped loudly (absent here, required in CI).

### 3. Go is authoritative when Go and SQL disagree

A version verdict has one authority: **Go**. The finding pipeline runs there, and
any SQL comparison is an optimisation. When they disagree, Go wins, because the
alternative is the two-writers-one-fact pattern (§5.2) with the database as the
second writer — a comparator correct in Go and disagreeing with the SQL doing the
same comparison is the defect that ships silently.

**If the SQL cannot express the comparison faithfully, the query does not do the
comparison** — it narrows the candidate set (by package name, distro, coarse
bounds) and Go decides the version relation on the narrowed set. This is not
hypothetical: `roundtrip_integration_test.go` proves against a real Postgres that
native text ordering sorts a pre-release `1.0~rc1` AFTER its release `1.0`, the
opposite of dpkg — so a query that ordered or compared versions as text would be
confidently wrong exactly where ADR-014 says it matters. The test also confirms
version strings round-trip byte-identical, so what Go compares is what was stored.

A future SQL-side comparison (a Postgres function, a generated ordering column) is
permitted only if it is differential-tested against Go the way the libraries are —
never trusted because it looks equivalent.

### Scope

dpkg and rpm; the operators advisories use (`<`, `<=`, `>`, `>=`, `==`) and the
range form `AffectedRange{Introduced, Fixed}` (vulnerable when installed is at or
above Introduced and strictly below Fixed — so a host patched to exactly the fixed
backport revision is cleared, the ADR-014 false-positive guard). The comparators
satisfy the order properties (antisymmetric, transitive, total), checked
exhaustively.

## Consequences

- The comparators are validated three ways that do not share our understanding:
  the distributions' static corpora, the live library differential, and the order
  properties. The first two carry provenance and a require-flag so they stay real.
- `DB_TEST_PKGS` gains `internal/version` and `internal/correlate` — the latter
  because its DB-backed integration tests (merge, DHCP survival, OS attribution)
  were guarded by `CVAP_TEST_DATABASE_URL` yet the package was in no DB test
  target, so they had been **skipping in CI**. A DB test that never runs against a
  DB is the test-that-proves-nothing shape; both now run in the gate.
- Nothing consumes the comparators yet (P3.2/P3.3): the operators and
  `AffectedRange` are the interface advisory matching will drive. Proved here is
  correctness and the order properties; using them in situ is the next phase.

## Review trigger

Refresh the vendored corpora (per each `PROVENANCE.md`) when a distribution
publishes new version-comparison test cases; re-pin the commit. Revisit the
Go-authoritative decision only if a measured, unavoidable need for SQL-side
comparison arises — at which point it is differential-tested against Go, not
substituted for it.
