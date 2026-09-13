# CVAP — CyberSentinel Vulnerability Assessment Platform

Distributed vulnerability scanner. Central Control Plane, remote Scan Points, observation-first data flow.
Architecture: `docs/architecture-v2.md`. Plan: `docs/execution-plan.md`. Decisions: `docs/adr/`.

## Stack

Go 1.26 (control plane, scan points, agents) · Python 3.12 (knowledge pipelines) · PostgreSQL 16 · gRPC/protobuf · React + TypeScript.

## Layout

```
cmd/            binaries: cvap-core, cvap-scanpoint, cvap-cli, cvap-engine-*
internal/
  control/      control plane services (auth, tenancy, asset, scan, policy)
  dispatch/     job broker + dispatch + ingest
  scanpoint/    scan point runtime, lease client, engine host
  engines/      discovery, fingerprint, credhost — separate processes (ADR-027). A scan-point
                `rules` engine (request-coupled checks, ADR-013) is not built yet;
                the Core-side evidence-based rule engine is internal/rules
                enginerate/ is the shared packet budget: ONE model, because
                make safety asserts wire-to-charged against one (ADR-048)
  correlate/    observations -> assets, then assets -> findings. What writes an
                asset from evidence (ADR-006) — the only other writer is an operator's
                adjudication of the identity queue (ADR-097); merge and rule DECISIONS
                are pure and live in domain/ and rules/
  rules/        Core-side evidence-based rule engine (ADR-013, ADR-050). Closed
                evaluators, open rule rows. No I/O.
  domain/       observation, asset, finding models — no I/O in here
  store/        postgres access, RLS-aware
  logging/      slog setup + credential redaction
  protocol/     wire-contract conformance tests. No production code.
proto/          FROZEN wire contract. See ADR-022 before touching.
gen/            generated Go bindings, committed. Never hand-edit — make proto-gen.
migrations/     numbered SQL. RLS + partitioning in the creating migration.
knowledge/      python ingestion pipelines
lab/            vulnerable target compose + golden corpus
web/            React UI
```

## Commands

```
make build        make test         make lint         make ci
make up           make down         # dev stack: postgres + minio
make lab-up       make lab-down     # isolated scan lab, two segments
make migrate-up   make migrate-new NAME=x
make proto        # lint + additive-only check + gen/ matches proto/
make proto-gen    make proto-tools  # regenerate bindings; install pinned toolchain
make safety       # scope-enforcement gate — must pass before any merge
make corpus-check # golden corpus diff
```

`safety` is the scope-enforcement gate (egress capture in the lab). `corpus-check`
(session 16) diffs a real scan of the lab against the hand-labelled golden corpus
in `lab/corpus/`: a label half that runs everywhere (schema + labels vs the
containers' own account of themselves in `ground-truth.json`) and a scan half —
the six §6.2 accuracy gates — that runs when the lab is reachable and is fatal in
CI via `CVAP_REQUIRE_LAB=1`. The corpus is labelled from the containers, never
from the scanner, so a pass is not the scanner agreeing with itself. A gate that
silently passes is worse than one that fails, because the first gets trusted —
which is why the skip names what it skipped.

## Non-negotiables

These are enforced by hooks and reviewed by subagents. Full detail: `/cvap-invariants`.

1. Scan Points emit **Observations**. They never write assets or findings.
2. No `zone` column on assets. Exposure is derived from observations.
3. Every tenant-scoped table has `tenant_id` + an RLS policy **in the same migration that creates it**.
4. Findings carry a `rule_id` always, `vuln_def_id` optionally. SAST dedup keys on symbol, never line number.
5. Distro packages match against vendor advisories, not NVD version ranges.
6. `proto/` changes are additive-only within a major version.
7. Jobs carry a lease epoch. Non-`reassign_safe` jobs fail on lease loss; they do not retry.
8. Credentials are memory-only on scan points, zeroised on completion or abort.
9. Detection establishes evidence without achieving impact. No data extraction, no shells, no exfiltration.
10. Scanning targets outside `lab/scope.txt` are blocked during development.

## Scope discipline

MVP scope is frozen in `docs/execution-plan.md` §2. Out of scope for the 8-week build: CVE matching,
credentialed assessment, DAST, API testing, SAST, cloud, containers, agents, reporting engine, Kubernetes.
If a change adds one of these, stop and say so rather than building it. Two of them have since been
authorised by ADR: advisory matching (Phase 3, ADR-059 onward) and Linux/SSH credentialed inventory
(Phase 4, ADR-081/084/086 onward) — those are in scope; the rest of the list still is not.

## Review

Run `security-reviewer` and `scan-safety-auditor` on anything touching scanning, credentials, or scope.
Run `schema-auditor` on any migration. Run `adr-compliance` before merging cross-cutting changes.
