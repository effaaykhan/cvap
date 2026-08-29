# CVAP — CyberSentinel Vulnerability Assessment Platform

Distributed vulnerability scanner. Central Control Plane, remote Scan Points, observation-first data flow.
Architecture: `docs/architecture-v2.md`. Plan: `docs/execution-plan.md`. Decisions: `docs/adr/`.

## Stack

Go 1.23 (control plane, scan points, agents) · Python 3.12 (knowledge pipelines) · PostgreSQL 16 · gRPC/protobuf · React + TypeScript.

## Layout

```
cmd/            binaries: cvap-core, cvap-scanpoint, cvap-cli
internal/
  control/      control plane services (auth, tenancy, asset, scan, policy)
  dispatch/     job broker + dispatch + ingest
  scanpoint/    scan point runtime, lease client, engine host
  engines/      discovery, fingerprint, rules
  domain/       observation, asset, finding models — no I/O in here
  store/        postgres access, RLS-aware
proto/          FROZEN wire contract. See ADR-022 before touching.
migrations/     numbered SQL. RLS + partitioning in the creating migration.
knowledge/      python ingestion pipelines
lab/            vulnerable target compose + golden corpus
web/            React UI
```

## Commands

```
make build        make test         make lint
make lab-up       make lab-down     make corpus-check
make safety       # scope-enforcement suite — must pass before any merge
make migrate-up   make migrate-new NAME=x
```

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
If a change adds one of these, stop and say so rather than building it.

## Review

Run `security-reviewer` and `scan-safety-auditor` on anything touching scanning, credentials, or scope.
Run `schema-auditor` on any migration. Run `adr-compliance` before merging cross-cutting changes.
