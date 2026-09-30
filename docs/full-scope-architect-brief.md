# CVAP — full-scope architect brief

**Audience:** a principal security architect and software architect being asked to scope and
design the complete 15-volume product.
**Purpose:** everything needed to understand what exists, what it commits you to, what is
missing, and what must be decided before any of it can be designed.
**Date:** 2026-09-30. Every figure below was measured against the running system on that
date, not estimated. Where something is unmeasured it says so.

> **Read this first.** The fifteen volumes describe a substantially larger product than the
> one this codebase was scoped and costed for. Seven of them are, in writing, out of scope in
> `docs/execution-plan.md` §2. They are not *unbuilt*; they were *excluded*. Treating the gap
> as "remaining work on CVAP" will produce a wrong plan. See §9.

---

## 1. What CVAP is today, in one paragraph

A distributed **network** vulnerability scanner. A central Control Plane owns all state and
all judgement; remote Scan Points run engines as separate processes and emit *observations*
only. Correlation turns observations into assets, then assets into findings. It is
multi-tenant with row-level security, does credentialed Linux inventory over SSH, matches
installed packages against vendor advisories, prioritises by CISA KEV and FIRST EPSS, and
maps findings to MITRE ATT&CK techniques. It has never exploited anything and is
architecturally prevented from doing so.

It is **not** an application security platform. There is no crawler, no HTTP attack engine,
no SAST, no DAST, and none of the twenty-four web vulnerability classes in Volume 8.

---

## 2. Measured scale

| | |
|---|---|
| Go production code | **53,088 lines** |
| Go test code | **37,645 lines** (71% of production) |
| Go packages | 46 |
| Architecture Decision Records | **109**, all Accepted |
| Database migrations | **52** |
| Database tables | 67 |
| HTTP API routes | **49** |
| Detection rules | 14 |
| Mutation tests (all killed) | **143** |
| Fuzz tests | **0** |

### Largest packages (production lines)

```
11,802  internal/store          persistence, RLS-aware, the only door to Postgres
 8,802  internal/control/api    operator HTTP API, 49 routes, OpenAPI-generated client
 5,445  internal/scanpoint      scan point runtime, lease client, engine host
 3,881  internal/dispatch       job broker, dispatch, result ingest
 2,599  internal/correlate      observations -> assets -> findings
 2,082  internal/engines/fingerprint
 1,870  internal/domain         PURE model and decisions, no I/O
   998  internal/rules          closed evaluators, open rule rows
   951  internal/credscan       credentialed inventory
   894  internal/engines/discovery
```

---

## 3. Repository structure

```
cmd/
  cvap-core                 control plane server (API + dispatch + correlation)
  cvap-scanpoint            scan point runtime
  cvap-cli                  operator CLI (bootstrap, tenant, enrollment)
  cvap-engine-discovery     host/port discovery engine      (separate process, ADR-027)
  cvap-engine-fingerprint   service/TLS/SSH fingerprinting  (separate process)
  cvap-engine-credhost      credentialed SSH inventory      (separate process)
  cvap-engine-noop          contract-conformance engine for tests
  cvap-credscan             credentialed scan driver
  cvap-openapi              emits the OpenAPI spec from the route registry (no DB)

internal/
  control/      api (HTTP), ca (internal PKI), credential (PHC hashing),
                enrollment (token -> client cert)
  dispatch/     job broker (Postgres SKIP LOCKED), dispatch, ingest
  scanpoint/    runtime, lease client, engine host, credential handling
  engines/      discovery, fingerprint, credhost, enginerate (shared packet budget)
  correlate/    observations -> assets (ADR-006), assets -> findings, presence verdict
  rules/        Core-side evidence-based rule engine. Closed evaluators, no I/O
  domain/       PURE model + decisions: identity, attribution, release, kernel,
                cadence, coverage, presence. NO I/O of any kind
  store/        PostgreSQL access, RLS-aware, the only door to the database
  credscan/     credentialed inventory parsing
  credsource/   credential sourcing
  hostkeytrust/ SSH host key trust root
  sshalgo/      SSH algorithm policy
  scope/        scan scope enforcement
  target/       target expansion
  enginepolicy/ per-engine policy
  enginewire/   engine job contract
  protocol/     wire-contract conformance tests. NO production code
  logging/      slog setup + credential redaction
  version/      distro version comparators (dpkg, rpm)

proto/          FROZEN wire contract (ADR-022, additive-only within a major version)
gen/            generated Go bindings, committed, never hand-edited
migrations/     52 numbered SQL migrations; RLS + partitioning in the creating migration
knowledge/      Python ingestion: usn_ingest, risk_ingest (KEV/EPSS), attack_ingest,
                import_product_map
lab/            vulnerable-target compose, scope.txt, golden corpus + ground truth
test/           e2e, load (SLO gates), safety (egress capture), corpus
web/  +  internal/control/api/web/   React 19 + TypeScript + Vite console
deploy/         compose deployment, secrets
docs/           architecture-v2, execution-plan, 109 ADRs, specs, session map
.claude/        agents, skills, hooks (scope guard, contract freeze, mutation gate)
```

---

## 3a. How the two people on this project work

The architect should know this before proposing anything that touches the console, because
the division is enforced by tooling rather than convention and a plan that ignores it will
produce commits the repository refuses.

**Two people, one OS account, one clone, two worktrees.**

```
/home/soc/cvap                 main       effaaykhan  <kf582993@gmail.com>       backend
/home/soc/cvap/.worktrees/ui   feat/ui    Nidhi Choudhari <...@users.noreply>   console
```

**The directory decides the author, and a hook enforces it.** `extensions.worktreeConfig` is
enabled and each worktree carries its own `user.email` via `git config --worktree`. A
`pre-commit` hook reads the working tree's toplevel and **refuses** a commit whose author
does not match that directory. GitHub credits a commit to the owner of the author email, so
a mis-credited commit is only visible after it reaches GitHub, which is too late to fix
quietly. The hook refuses it instead.

**Ownership is declared in `.github/CODEOWNERS` and it is deliberately asymmetric:**

```
*                                            @effaaykhan     everything by default
/internal/control/api/web/                   @nidhichoudhari the console
/internal/control/api/web/src/api/schema.ts  @effaaykhan     GENERATED from the route registry
/internal/control/api/routes.go              @effaaykhan     the API surface
/internal/control/api/handlers_*.go          @effaaykhan     the handlers
```

The generated client sits inside the console directory but is owned by the backend, because
it is produced by `make ui-types` from the Go route registry and a CI gate (`make ui-verify`)
diffs it. **It is the one file in her tree that she must not edit** — and the one the backend
must regenerate whenever an API field changes, or her typecheck breaks through no fault of
hers.

**Practical consequences for any plan:**

- Backend work and console work land in **separate commits by different authors**, always.
  A change that spans both (a new API field plus its rendering) is two commits in two
  worktrees, not one.
- An API change that alters the response shape **breaks her build until `schema.ts` is
  regenerated**. The backend does that as part of its own change, not as a follow-up.
- A required (non-`omitempty`) new field breaks every test fixture constructing that type.
  Backend fixes the shared factory; she fixes anything she has added.
- `CONTRIBUTING.md` carries the full merge runbook (commit in the worktree → gate in the
  worktree → merge to main → rebuild the bundle → relink → restart → confirm the served
  bundle hash changed). It is not summarised here because it is operational detail that
  changes; read it there.
- Backend-to-console handoffs are written as a **spec document**, not as tickets — see
  `docs/attack-technique-console-spec.md` for the worked example. The spec carries the
  wording contracts the API cannot enforce (what an empty array means, what must never be
  implied), because those are exactly what gets lost in a handoff.

**Why this matters to an architect scoping Volumes 4–8.** Every one of those volumes has a
console surface. The current model has one person on the console and one on everything else,
and the console is already the narrower resource. Any plan that adds five engines without
adding console capacity will produce five capabilities with no surface — which is a shape
this project has an explicit standing rule against.

## 4. How it works end to end

1. An operator creates a **scan** against targets, governed by a **scan policy** (allowlist,
   exclusions, rate limits, time windows, safety mode).
2. Core **decomposes** scan → jobs → tasks and offers them through a broker built on
   Postgres `SELECT ... FOR UPDATE SKIP LOCKED` (ADR-003; NATS deliberately deferred).
3. A **Scan Point** connects **outbound only**, over mTLS with a client certificate it
   obtained by redeeming an enrollment token (ADR-005, ADR-018). Core never connects inward.
4. Jobs carry a **lease with a fencing epoch**. Non-`reassign_safe` jobs fail on lease loss;
   they never retry (non-negotiable #7).
5. The Scan Point runs **engines as separate processes** (ADR-027) and streams back
   **observations** — never assets, never findings (ADR-006, non-negotiable #1).
6. Results are submitted in **chunks, idempotently**, with a terminal ack that promotes them
   from `pending` to `accepted` (ADR-026). An in-flight submission is invisible to the
   pipeline.
7. **Correlation** sweeps accepted observations per HOST, resolves identity through ranked
   keys with retained merge evidence (ADR-007), and writes assets. It is the only writer of
   assets besides an operator adjudicating the identity queue (ADR-097).
8. **Findings** come from two paths: the Core-side rule engine over evidence (ADR-013/050),
   and advisory matching of installed packages against vendor advisories (ADR-059+).
9. Findings are **prioritised** lexicographically: KEV > exposure > criticality > EPSS >
   CVSS (ADR-069), and **mapped to ATT&CK** techniques as labelled inferences (ADR-105).

---

## 5. Data model

67 tables. Grouped by concern:

**Tenancy & auth** — `tenants`, `users`, `roles`, `user_credentials`, `sessions`,
`tenant_auth_config`, `oidc_auth_requests`, `audit_events`.

**Topology & fleet** — `scan_zones`, `network_ranges`, `scan_points`,
`scan_point_capabilities`, `scan_point_certificates`, `enrollment_tokens`.

**Scanning** — `scan_policies`, `policy_scope_rules`, `scan_policy_credential_profiles`,
`scans`, `scan_targets`, `scan_jobs`, `scan_tasks`, `job_leases`, `kill_switches`,
`kill_acks`, `cancel_acks`, `result_submissions`.

**Observation & asset** — `observations` (monthly partitions, ADR-016), `assets`,
`asset_addresses` (+ presence verdict, ADR-108/109), `asset_identity_keys`,
`asset_identity_key_sightings`, `asset_resolution_queue`, `asset_relationships`,
`services`, `software_components`, `identity_settings`.

**Findings** — `findings`, `finding_history`, `finding_exposure`, `evidence`, `remediations`,
`reports`.

**Knowledge (global, untenanted, ADR-030/063)** — `rule_packs`, `rules`,
`vulnerability_defs`, `vendor_advisories`, `advisory_fixed_packages`, `advisory_vuln_map`,
`rule_vuln_map`, `kev`, `epss`, `product_packages`, `release_coverage`,
`knowledge_feed_status`, `attack_techniques`, `cve_techniques`, `rule_techniques`.

**Credentials** — `credential_profiles`, `credential_grants`.

### Live data volumes (this installation)

```
epss                378,567      observations            6,089
advisory_vuln_map    47,952      services                2,628
vulnerability_defs    6,028      scan_tasks              2,098
advisory_fixed_pkgs   3,114      kev                     1,723
cve_techniques        1,183      attack_techniques         799
vendor_advisories       700      assets / addresses        512
```

---

## 6. The ten non-negotiables

Enforced by hooks and reviewed by subagents. **Any design that violates one of these is
wrong by construction, not by preference.**

1. Scan Points emit **Observations**. They never write assets or findings.
2. No `zone` column on assets. Exposure is derived from observations.
3. Every tenant-scoped table has `tenant_id` + an RLS policy **in the same migration that
   creates it**.
4. Findings carry a `rule_id` always, `vuln_def_id` optionally. SAST dedup keys on symbol,
   never line number.
5. Distro packages match against vendor advisories, not NVD version ranges.
6. `proto/` changes are additive-only within a major version.
7. Jobs carry a lease epoch. Non-`reassign_safe` jobs fail on lease loss; they do not retry.
8. Credentials are memory-only on scan points, zeroised on completion or abort.
9. **Detection establishes evidence without achieving impact. No data extraction, no shells,
   no exfiltration.**
10. Scanning targets outside `lab/scope.txt` are blocked during development.

**#9 is the one that shapes Volumes 6–8 most.** A DAST engine that confirms SQL injection by
extracting a row, or an exploit module that returns a shell, contradicts it. Either the
volumes are re-scoped to evidence-without-impact, or #9 is changed by ADR with full
awareness of what that costs. That is an architectural decision, not an implementation
detail.

---

## 7. Quality bar in force

Any new module is expected to clear the same gates. This is unusually strict and the
architect should cost it in.

```
make build / test / lint / ci      gosec, golangci-lint, go vet — all at zero findings
make migrate-verify                every migration applies up / down / up on a fresh DB
make store-test                    DB-backed suites (a bare `go test ./...` skips them all)
make rls-test                      tenant isolation proven as the application role
make safety                        egress capture in the lab; scope enforcement gate
make corpus-check                  golden corpus diff against hand-labelled ground truth
make loadtest                      §5 SLOs at 10k/50k assets
make mutate                        143 mutations; a surviving mutation FAILS the build
make ui / ui-verify                generated client must match the route registry
```

Practices that are cultural, not just tooling, and that the codebase's history shows are
load-bearing:

- **ADRs are frozen once Accepted.** They are superseded by a new ADR, never edited. A
  `protect-contracts` hook enforces it.
- **Claims carry measurements.** ADRs quote the query that produced their figures.
- **Gates that skip must say so loudly.** A silently-passing gate is treated as worse than a
  failing one, because the first gets trusted.
- **Decisions are pure.** Merge, identity, presence and rule logic live in `internal/domain`
  with no I/O, so they can be replayed over stored history when corrected.

---

## 8. What the schema already anticipates

These enum values exist **today** with no implementation behind them. They are reserved
slots, and they tell you where the original design expected the product to grow:

```
engine_kind     discovery, fingerprint, rules, host, dast, api, sast, cloud, advisory
finding_source  network, credentialed, dast, api, sast, config, cloud
execution_site  scan_point, core
safety_mode     safe, intrusive
```

So the job contract, the engine host, the finding model and the result-ingest path were all
designed to accept DAST/SAST/API/cloud engines. **That is the good news, and it is real** —
a new engine is a new process behind an existing contract, not a new pipeline.

---

## 9. Volume-by-volume status

Legend: **Built** = substantially complete and gated · **Partial** = real but incomplete ·
**None** = no implementation (verified by grep, not assumed).

| # | Volume | Status | Detail |
|---|---|---|---|
| 1 | Product Foundation | **Partial** | Vision, objectives, scope, roadmap, NFRs/SLOs in `execution-plan.md`. Threat model is embedded in that doc and `architecture-v2.md`, **not a standalone artefact**. 3 RBAC roles. No personas. |
| 2 | System Architecture | **Built** | 109 ADRs, multi-tenancy via RLS, distributed scan points, job broker, engines as processes. **Queues = Postgres `SKIP LOCKED`** by deliberate choice (ADR-003). **HA: none, out of scope.** Horizontal scaling: scan points yes, Core untested. |
| 3 | Asset Discovery Engine | **Built** — strongest area | ARP/ICMP/TCP discovery, TCP connect scanning, banner grabbing, service + TLS + SSH fingerprinting, OS attribution with provenance, scheduling cadence, asset inventory, and the presence verdict (ADR-108/109). |
| 4 | Web Crawler | **None** | 0 files. No crawl, spider, DOM, JS rendering, SPA, form discovery. |
| 5 | HTTP Engine | **Partial (minimal)** | HTTP used by rules only (headers, redirect). **No HTTP/2, WebSockets, multipart, proxy, compression or retry engine.** |
| 6 | SAST | **None** | `EngineSAST` is an enum placeholder. No lexer, parser, AST, CFG, DFG, SSA, taint, alias analysis, call graph — for **0 of 12 languages**. |
| 7 | DAST | **None** | `EngineDAST` is an enum placeholder. No spider, payload engine, response/differential analysis, attack chains. |
| 8 | Vulnerability Detection (24 web classes) | **None** | Zero of SQLi, XSS, SSRF, XXE, SSTI, LFI/RFI, CSRF, IDOR, deserialization, JWT, OAuth, GraphQL, prototype pollution, request smuggling… CVAP's 14 rules are network/TLS/exposure — a different class of defect entirely. |
| 9 | Rule Engine | **Built, narrower** | Closed evaluators + open rule rows (ADR-013/050), severity, confidence, metadata, versioning, CWE. **No rule language or compiler** — deliberate: a closed evaluator set is auditable, a rule DSL is not. |
| 10 | Knowledge Base | **Partial** | CVE 6,028 · advisories 700 · fixed packages 3,114 · KEV 1,723 · EPSS 378,567 · ATT&CK 799 techniques · CWE on 13/14 rules. **No CAPEC. No payload repository. No signature repository beyond fingerprint probes.** |
| 11 | Reporting | **Partial (CSV only)** | `/v1/findings.csv`, `/v1/assets.csv`, bounded and refuse-not-truncate. Trends and historical scans in the console. **No executive / technical / developer / compliance reports, no PDF.** |
| 12 | AI Layer | **None** | Verified: zero non-test references to any model provider. |
| 13 | DevSecOps | **None** | No repo/branch/PR scanning, no incremental scanning, no baselines, no policy gates. |
| 14 | Infrastructure | **Built** | 52 migrations, route registry + generated OpenAPI client, object store for evidence, internal CA + mTLS, memory-only zeroised credentials, `audit_events`, health/telemetry. **Caching minimal.** |
| 15 | Testing | **Built, one real gap** | 37,645 test lines, unit + integration + RLS + load/SLO + golden corpus + scope-safety + **143 mutation tests**. **Zero fuzz tests** — a genuine gap in a system whose whole job is parsing hostile input. |

### Honest completion figure

**Against the frozen MVP scope:** substantially complete, plus two ADR-authorised expansions
(advisory matching, credentialed Linux inventory).

**Against these fifteen volumes:** **5 Built** (2, 3, 9, 14, 15), **4 Partial** (1, 5, 10, 11),
**6 None** (4, 6, 7, 8, 12, 13) — a third by volume count, but **volume count flatters
badly**. Volume 6 (SAST across 12 languages) and Volume 8
(24 vulnerability classes with detection logic, evidence, confidence and remediation) are
each larger than everything CVAP has built in total. **Weighted by effort, 10–15% is the
defensible number.**

---

## 10. What must change architecturally to reach the full scope

These are the seams. An architect should assume each is a design workstream, not a task.

1. **Non-negotiable #9 vs. Volumes 7–8.** Proving SQLi, SSRF or deserialization usually means
   *doing* something. Decide: evidence-without-impact DAST (differential timing, error
   fingerprints, out-of-band callbacks with no data retrieved), or amend #9 by ADR. **This is
   the single largest decision in the brief.**
2. **Findings model.** Non-negotiable #4 says SAST dedup keys on *symbol*, never line number
   — already anticipated. But a web finding needs request/response evidence, a taint path
   needs a call chain, and `evidence` today is a summary plus an object-store pointer
   (ADR-015). Sizing and schema for those is unsolved.
3. **`execution_site`.** SAST runs on code, not a network. Does it run at the scan point, at
   Core, or in a third site (a CI runner)? The enum has two values.
4. **Scope enforcement.** `lab/scope.txt` and policy scope rules are *network* concepts. A
   repository, a branch and an application URL need an equivalent authorisation model, and
   #10 currently has no meaning for them.
5. **Credential model.** Memory-only and zeroised (#8) is right for SSH. DAST session
   management, OAuth flows and repository tokens are longer-lived and differently shaped.
6. **Knowledge base.** CAPEC, a payload repository and a signature repository do not exist.
   Payloads in particular are attack content — they need the same provenance, pinning and
   diffability the other feeds have (ADR-063), or they become unauditable.
7. **The wire contract.** `proto/` is frozen additive-only (ADR-022, #6). Every new engine
   kind must fit the existing job/observation shape or earn a major version.
8. **HA and horizontal scaling.** Out of scope today. Core is a single process; the broker is
   Postgres. Volume 2 asks for both.
9. **The 30-second wall.** `GET /v1/findings` at 50k assets currently exceeds the 30s
   operator transaction budget and returns 504. This is an existing, known, un-fixed
   performance defect and it will get worse with more finding sources.

---

## 11. Known defects and open items, stated

- **`loadtest` fails in CI**: findings list at 50k assets hits `OperatorBudget` (30s) → 504.
- **`corpus-check` fails in CI**: ground-truth drift.
- **`govulncheck` fails in CI**: GO-2026-6443, GO-2026-6348 unfixed.
- **Zero fuzz tests.**
- **0 of 512 assets carry an OS family** on the live estate — a consequence of the
  middlebox problem ADR-108 addresses; advisory matching is starved as a result.
- **ATT&CK CVE anchor covers 0 of 6,028 ingested CVEs** — the published dataset covers CISA
  KEV (commercial/appliance software) and CVAP's CVEs come from Ubuntu advisories. Stated
  honestly on the API rather than hidden.
- **Console rendering for ATT&CK not yet built** (spec exists:
  `docs/attack-technique-console-spec.md`).

---

## 12. What the architect must decide before designing anything

These cannot be inferred from the codebase. They are the brief's real input.

**Product**
1. Is the target one product or two — a network scanner and an AppSec platform sharing a
   control plane? The answer changes almost every subsequent decision.
2. Who is the buyer, and which volume do they pay for first?
3. Does non-negotiable #9 (evidence without impact) survive contact with Volumes 7–8? If it
   does, what counts as proof of an injection flaw?

**Scope and sequencing**
4. Which of the 12 SAST languages actually matter, and in what order? "All twelve" is not a
   plan.
5. Which of the 24 vulnerability classes are launch-critical?
6. Is the AI layer (V12) a product feature or a development aid?

**Delivery**
7. Team size, composition and timeline. The existing quality bar (mutation testing, ADRs,
   RLS-in-the-same-migration, golden corpus) costs perhaps 30–40% on top of raw feature work
   and is the reason the existing code is trustworthy. **Keeping it or relaxing it is a
   deliberate choice and should be made explicitly.**
8. Deployment model: on-prem, SaaS, or both? HA required at launch?
9. Compliance obligations (SOC 2, FedRAMP, ISO 27001)? These change the audit, logging and
   tenancy design.

**Constraints**
10. Is the frozen `proto/` contract allowed a major version bump?
11. Is Postgres-as-broker acceptable at the target scale, or is a real queue now required?

---

## 13. How to read the existing material

Priority order for an architect coming in cold:

1. `docs/execution-plan.md` §2 — the frozen scope and what was deliberately excluded.
2. `docs/architecture-v2.md` — the system design and ER model.
3. `docs/adr/000-index.md` — one-line summaries of all 109 decisions, with their reasoning
   and, importantly, the **alternatives that were rejected and why**. This is the densest
   source of design context in the repository.
4. `CLAUDE.md` (root) and the per-package `CLAUDE.md` files in `internal/store`,
   `internal/correlate`, `internal/domain`, `internal/engines` — these carry the invariants
   that the code assumes and that reviews enforce.
5. The 109 ADR titles are listed in `docs/adr/`; every one is Accepted and none may be edited.

---

## 14. Summary for the architect

You are not extending a prototype. You are extending a **53k-line, 109-ADR, heavily-gated
network scanner with real multi-tenancy and an unusually explicit design record** — into a
domain (application security) that it deliberately excluded and that is, by effort, several
times larger than what exists.

The good news is concrete: the engine contract, job model, result ingest, finding model and
enum space were all designed to accept DAST/SAST/API/cloud engines. A new engine is a new
process behind an existing contract.

The hard part is not the plumbing. It is **non-negotiable #9** — whether a scanner that has
never exploited anything can prove application-layer vulnerabilities, and if not, what is
given up when that rule changes.

---

## Appendix A — all 109 Architecture Decision Records

All Accepted. None may be edited; they are superseded by new ADRs only. Full text in
`docs/adr/`, one-line summaries with rejected alternatives in `docs/adr/000-index.md`.

- ADR-001: Go for core, scan points and agents; Python for knowledge pipelines
- ADR-002: PostgreSQL as system of record; RLS enforces tenancy
- ADR-003: Job dispatch via Postgres SKIP LOCKED; broker deferred
- ADR-004: Broker never exposed; dispatch service fronts it
- ADR-005: Scan point transport posture: outbound-only, scan-point-initiated mTLS
- ADR-006: Observation-first — scan points never write assets or findings
- ADR-007: Asset identity by ranked keys with retained merge evidence
- ADR-008: Zone is a property of observations; exposure is derived
- ADR-009: Rule / VulnerabilityDef / VendorAdvisory are separate entities
- ADR-010: Finding dedup keys are source-specific; SAST keys on symbol not line
- ADR-011: Scan / Job / Task three-level decomposition
- ADR-012: Job leases carry monotonic fencing epochs; reassign_safe gates retry
- ADR-013: Detection split — request-coupled at scan point, evidence-based at core
- ADR-014: Vendor advisories are authority for packages; CPE is flagged fallback
- ADR-015: Large evidence to object store; summary in Postgres
- ADR-016: Observations partitioned monthly, 90-day default retention
- ADR-017: Tenant-aware always, single-tenant by configuration
- ADR-018: PKI trust anchor is configuration, not assumption
- ADR-019: Knowledge data is signed; offline import supported
- ADR-020: Credentials just-in-time, scoped, memory-only on scan points
- ADR-021: Safe mode default; detection without impact
- ADR-022: Protocol versioning is additive-only within a major version
- ADR-023: Compose first; Kubernetes deferred
- ADR-024: Scan blast-radius controls
- ADR-025: Build-versus-consume boundary
- ADR-026: Result submission contract
- ADR-027: Engines are separate processes behind a job contract
- ADR-028: One pre-release correction to the frozen wire contract
- ADR-029: Schema tables the v2 ERD does not draw
- ADR-030: Knowledge tables are read-only to the application role
- ADR-031: Enrolment tenant lookup is a one-value SECURITY DEFINER function
- ADR-032: The store package exposes no path to a raw connection
- ADR-033: Pre-tenant resolution is a closed class
- ADR-034: No interceptor, middleware or tracing layer may render message bodies
- ADR-035: A hand-written type holding a secret stores it in a `func() string`
- ADR-036: The sweep enumerates tenants, and that is the only unscoped read
- ADR-037: Empty means deny for permission lists, unrestricted for constraint lists
- ADR-038: A secret field is a func of a type that can be zeroised
- ADR-039: Translated address forms expand exclusions and do not expand allows
- ADR-040: A target that names an address must parse as one, or the job is refused
- ADR-041: Pre-tenant resolution is a closed class of three
- ADR-042: Targets are canonicalised once at planning, and re-canonicalised at the scan point
- ADR-043: The route registry is the API contract, and the OpenAPI document is emitted from it
- ADR-044: Target canonicalisation, restated with three claims corrected
- ADR-045: OIDC identity is the subject, the client is public, and the issuer is a network the deployment chooses to trust
- ADR-046: OIDC, restated with the SSRF guard made true and two claims corrected
- ADR-047: The discovery engine may open sockets, and connect scanning is what it may do with them
- ADR-048: The fingerprint corpus is signed content, under a static policy it cannot widen
- ADR-049: Probes have kinds, and a key exchange is not a payload
- ADR-050: The rule engine is closed evaluators and open rules
- ADR-051: A scope narrowing reaches an in-flight job at its next lease renewal
- ADR-052: A CSV export refuses over its cap rather than truncating, and export is its own permission
- ADR-053: The operator SPA is a public static route in the one registry, and its client is a third registry
- ADR-054: What may live in the repo, now that it is private
- ADR-055: The enrollment-token prefix, and its now-half-moot secret-scanning rationale
- ADR-056: A fault worth testing is one the deployed binary can experience
- ADR-057: Credential zeroisation is immediate and independent of submission
- ADR-058: The load test enforces a coarse ceiling in CI and the precise SLO locally
- ADR-059: Phase 3 sequences comparators → advisories → KEV/EPSS → NVD, behind a real-network validation
- ADR-060: P3.3's OS-attribution entry condition, measured against a real host and failed (supersedes ADR-059 §P3.3)
- ADR-061: Unauthenticated OS attribution — family, nullable release, confidence, and a reviewable service precedence
- ADR-062: The version comparators are validated against the distributions' own corpora and libraries, and Go is authoritative over SQL
- ADR-063: The knowledge-import role is scoped to exactly the knowledge tables
- ADR-064: Release resolution by upstream version band
- ADR-065: Release-resolution confidence tiers, and the service-coverage bound
- ADR-066: The two-vote release threshold is reasoned, not validated
- ADR-067: The advisory coverage window is data, and a release past it is cannot-know
- ADR-068: The advisory assessment state is a server-owned enum on the asset
- ADR-069: KEV/EPSS prioritisation — KEV dominates, absence is not a low value
- ADR-070: Advisory findings — turning a match into a finding, and the model that carries it
- ADR-071: The advisory-finding dedup key depends on content, and a map change re-keys it
- ADR-072: An advisory finding's confidence is the minimum of its inference inputs
- ADR-073: The advisory-confidence inputs are 1.0 pass-throughs today, and min() is untested
- ADR-074: The exposure term derives from zone type; the never-written column is dropped
- ADR-075: A narrow credentialed slice as a validation instrument — overruling the S38 hold
- ADR-076: The credentialed slice is a measurement instrument; the credential stays in the runtime
- ADR-077: The validation instrument does not emit observations; the release-precedence rule is built dormant
- ADR-078: Unauthenticated advisory matching cannot observe the Debian revision — a structural precision limit
- ADR-079: A safe-mode scan reports on services that volunteer a banner, not services that exist
- ADR-080: A single vote that uniquely narrows to one release resolves, at reduced confidence
- ADR-081: Credentialed assessment moves next, ahead of B28 and the console
- ADR-082: Unauthenticated advisory-matching precision worsens monotonically as a host is better maintained — the decisive case
- ADR-083: Banner capture is non-deterministic, and it silently moves release resolution between vote tiers
- ADR-084: Phase 4 leads with credentialed assessment — the decision, and the arc that reached it
- ADR-085: The ADR-082 measurements, re-verified under the fixed scan point
- ADR-086: Credentialed SSH authenticates through a runtime signing agent; the ed25519 zeroise guarantee is full and verified
- ADR-087: B26 closed — credentialed rpm-in-situ, the exit-criterion result, and the EVR bug the real advisory found
- ADR-088: The fleet credentialed path is unexercised end-to-end; its acceptance is a real-pipeline refutation
- ADR-089: ADR-077 is correct as a unit but unreachable under the real sweep — a package-only host derives no family, so deriveRelease is skipped
- ADR-090: A credentialed observation resolves family and release itself, ahead of the inferred-family gate
- ADR-091: The credential grant crosses the wire — cred_user and known_hosts on the assignment, the secret on the grant, and the four things the route had to get right
- ADR-092: The credentialed route is proven end to end on the lab, and both SSH clients offer one host-key preference
- ADR-093: The fleet credentialed run on the production route — the sixteen close, and the kernel matcher cannot see which kernel runs
- ADR-094: A key CVAP observed is trust material at an address only after two scans there; an address handover is queued, not attached
- ADR-095: Provenance ranks regardless of recency — an inferred attribution never overwrites an exact one
- ADR-096: A key rotation with service continuity attaches; continuity narrows the window and verifies nothing
- ADR-097: An operator's word is the only verification — the identity queue's verbs
- ADR-098: The finding list is as slow as the plan the driver reaches — the shape is decided by measuring both plans, and the load gate budgets each measurement
- ADR-099: The running kernel is read, not inferred from the inventory — `uname -r` is the third command, and a kernel package at any other version is inventory
- ADR-100: The identity queue pages, a refusal is recorded, and the operator holds the other four verbs — B39's second slice
- ADR-101: Every transaction carries two bounds, because statement_timeout is not one
- ADR-102: Three of ADR-101's claims were false, and the login 504 was an oracle
- ADR-103: An open port is durable evidence; the rule engine does not see it yet
- ADR-104: A seen-only port needs a migration after all
- ADR-105: An ATT&CK technique is an inference about a weakness, never an observation of an attack
- ADR-106: A zero read from a column nobody writes is not evidence
- ADR-107: The correction needed correcting — an ADR about instruments, measured with a bad one
- ADR-108: A host that answers is not a host that exists
- ADR-109: A scan target is an instruction, not a declaration of the subnet mask