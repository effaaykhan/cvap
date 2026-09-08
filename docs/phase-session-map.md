# CVAP — Phase & Session Map

What each session delivered, what it found, and where the build stands against
`docs/execution-plan.md` §2. This is the human-readable companion to the git log
and the ADR index; the failure patterns in §9 are the part that lived only in
agent memory until now.

> **Provenance note.** A `phase-session-map.md` was believed to exist covering
> through session 8. It was never committed to the repo — no tracked history, no
> stash. This file is written fresh from the commit history (76 commits), the ADR
> set (001–058), the migrations (0001–0032), the CI workflow, and the recurring
> agent-memory findings. Treat sessions 1–8 below as reconstructed from commits,
> not from that lost document.

---

## 1. Phases

| Phase | Execution-plan mapping | Sessions | State |
|-------|------------------------|----------|-------|
| Phase 0 — contracts & foundation | Week 1 (§4) | 1–4 | complete |
| Phase 1 — control plane, scan-point protocol | Weeks 2–3 | 5–11 | complete |
| Phase 2 — discovery, fingerprint, resolution, findings, UI, hardening | Weeks 4–8 | 12–23 | **complete (this session closes it)** |
| Phase 2 validation — real-network accuracy | S24 | 24 | done; P3.3 entry condition measured & **failed** (ADR-060) |
| Phase 3 — knowledge pipeline / CVE matching | §7 path-to-sellable | 25+ | sequenced (ADR-059); **blocked** on B21 (attribution) + B22 (version extraction) before P3.3 (ADR-060); safe-mode design validated (S24) |

Weeks and sessions are not one-to-one. The eight-week plan assumed a team; this
build is sequential under one operator with Claude Code, so a "week" of the plan
spans several sessions and the review load is heavier per feature (§1.3 of the
plan predicted exactly this).

---

## 2. Session ledger

### Phase 0 — contracts & foundation

- **S1** — Claude Code config (skills, agents, hooks, ADR index). ADR-001..027
  accepted. Proto contract written into execution-plan §4.2. *The decision
  baseline and the wire contract text, before any feature code.*
- **S2** — Repo skeleton, structured logging (slog + credential redaction), CI,
  the scope-guard hook, gitignore tests.
- **S3** — Scan-point wire contract in `proto/`, generated Go bindings committed,
  buf lint + additive-only gates.
- **S4** — Wire-contract security sweep: `RotateRequest` field 3 removed and
  reserved; grpc 1.82.1, Go 1.25. **Found:** the additive-only baseline was
  comparing the contract against itself — a gate that proved nothing. Fixed.

### Phase 1 — control plane & scan-point protocol

- **S5** — Full v2 schema as 14 numbered migrations. schema-auditor and
  write-migration corrected: evidence is **not** partitioned (ADR-016), `WITH
  CHECK` required on every RLS policy.
- **S6** — `internal/store`, the RLS-aware data-access layer. CI fix: `x/text`
  advisory reachable once pgx pulled it onto a path.
- **S7** — Enrollment service, its CA, enrollment tokens. ADR-035: secrets live in
  func fields; gosec fixed via `os.Root`.
- **S8** — Dispatch (broker, Connect stream, leases, kill switch) and Ingest
  (pending state, epoch rejection, the ratchet). Cancellation, policy ceilings,
  Core-side scope enforcement, policy levers on the wire, empty-list asymmetry
  recorded (ADR-037). **Found:** a protect-contracts bypass — closed by hashing
  outcomes instead of guessing spellings.
- **S9** — Scan-point runtime as two processes over real TLS. Translated address
  forms expand exclusions only; supersession stops needing a bypass (ADR-039).
  `make mutate`. ADR-040: an address-shaped target must parse as one.
- **S10** — One canonical target form, computed twice (ADR-042). The operator API.
  **Found:** three controls that existed but could not be reached (no route); the
  RLS fixtures the sweep found missing. `make ci` becomes the whole runner and
  skips loudly.
- **S11** — Single sign-on (OIDC), so the primary deployment mode has a login.
  **Found:** ten defects across two reviews, and the pattern in them (pre-auth KDF
  and pool starvation — the probes-not-reading lesson). Three recurring patterns
  become gates; one of them structurally cannot be.

### Phase 2 — discovery through hardening

- **S12** — Engine selection by kind. The discovery engine (ADR-047). **Found:**
  four things running it found; CI found two things the local run could not; a
  packet-capture audit found five, measured not read; three stale mutation
  declarations. The rate budget counts packets now, and the lab can prove it.
- **S13** — Service identification. **Found:** the rate ceiling was 2.24× loose. A
  test that names what the corpus must contain, and the deferral's likely fix.
- **S14** — Identity keys: an SSH key exchange that stops where it says it does
  (ADR-049). Observations become assets; one asset survives a DHCP change.
- **S15** — The rule engine, Core-side, closed evaluators over open rule rows
  (ADR-050). The first non-CVE findings a human can verify. **Four rules deferred**
  (see backlog).
- **S16** — Accuracy is measurable now: the lab, the golden corpus, the §6.2 gate.
  The `ci` line and the workflow become one registry, reconciled by a script.
  **Found:** CI surface divergence — a gate in `make ci` was not a gate in Actions.
- **S17** — `make safety` in its full week-8 form: the runtime send-path on a wire,
  and a mid-scan scope lever (ADR-051). Safe-mode mutations re-anchored after
  `budget()`'s clamp moved.
- **S18** — The operator read API: findings with evidence, the surface the UI
  consumes. Export is its own permission and its own ADR (ADR-052). **Found:** the
  two-writers-one-fact exposure-count discrepancy (see §9).
- **S19** — The operator UI. The generated client made a third registry.
  **Found:** the security-header class belongs in a middleware, not a write-helper
  (serving bytes bypassed writeJSON's headers). ADR-053 (SPA is a public static
  route in the one registry), ADR-054/055 (the public-to-private repo move).
- **S20** — The §6.4 distributed fault-injection matrix, F1–F6b, each case
  sabotaged to prove the test fails without the fix. **Found/fixed:** result loss
  when the first chunk hits RETRY_LATER; `HeartbeatTimeout` was a Go const and a
  SQL literal that could drift; a self-aborted job's results must be enqueued
  before shutdown exits. ADR-026 local durability scheduled; ADR-057 zeroise
  ordering decided.
- **S21** — The 10k-asset load test: shape-validation harness, synthetic seeder,
  in-process load harness, wired into CI as a coarse ceiling with the precise SLO
  local (ADR-058). A verdict on the overshoot.
- **S22** — Synthesize scan-point health on `GET /v1/scan-points`. Extract the
  argon2id hasher into `internal/control/credential`. The single-node installer
  (Compose, image, two CLI commands). The operator runbook, written from the code
  not the ADRs.
- **S23 (this session)** — Deploy-path hardening: fixed the install path so it
  reaches an enrolled scan point; **refuse a scan no scan point can run** (the
  silent-success finding — a COMPLETED scan that dispatched nothing); bootstrap
  verifies its own login; reach the deployment by name or IP, not only loopback;
  operator console self-service password change and a SOC design pass; configurable
  dev-CA validity; require `--domain` at bootstrap and an audited `tenant
  set-domain`. **Then this close-out — docs and Phase 3 sequencing, no feature
  code.**
- **S24 — Phase 2 real-network validation** (owned machines, `192.168.93.0/24`,
  safe mode). First accuracy measurement against hosts not built to be found.
  **Found, and named rather than smoothed over:**
  - **Discovery is TCP-connect-only** (ARP/ICMP/SYN deferred, need `CAP_NET_RAW`),
    so a default-firewalled Windows host reads as *down* and a `/24` sweep blocks in
    `connect()` on dropped SYNs — the lab's 100% recall is partly an artifact of
    lossless, firewall-free containers.
  - **OS attribution fails P3.3's entry condition (ADR-060).** Against Metasploitable
    (Ubuntu 8.04), asset OS is `null`; the only hint was a wrong-distro `Debian`
    (from `Debian-8ubuntu1`), no release, unpromoted — despite banners stating Ubuntu
    three times. Blocked on **B21** (attribution → release + promote) and **B22**
    (version extraction). `osHint` is §5.6's fourth instance.
  - **Service ID ~26%** on Metasploitable (6/23 ports): FTP/SSH/SMTP/MySQL hit;
    **HTTP/Apache, SMB/Samba, VNC, PostgreSQL, NFS, RPC, IRC, X11, AJP, RMI, distcc,
    r-services** all `method:none` — ~14 corpus gaps, each a Phase-3 input.
  - **Two lifecycle findings:** scans stay `running` after all jobs finish; dead
    addresses become assets (252 phantom assets from the `/24` sweep).
  - **★ Safety held under the most adversarial conditions available.** Scanning ~15
    deliberately-exploitable Metasploitable services, the scanner sent **zero payload
    probes and zero authentication attempts** — every observation was `method:
    banner` (read) or `none`, `safety_mode=safe` throughout. ADR-021's
    detection-not-exploitation line held against a host built to punish crossing it.
    This is the strongest evidence to date that the safe-mode design works: a scan of
    Metasploitable extracted only what the services *volunteered*.

---

## 3. Artifact inventory (as of S23)

**ADRs.** 001–058 accepted (`docs/adr/`, index at `000-index.md`). Corrections are
recorded as new ADRs, never edits: 028 corrects the pre-release contract; 041
supersedes 033; 044 corrects 042; 046 corrects 045. The freeze rule holds — a
committed ADR is superseded, never rewritten.

**Migrations.** 0001–0032. Every tenant-scoped table carries `tenant_id` + RLS
(`USING` and `WITH CHECK`) in its creating migration. `observations` is
range-partitioned from creation; `evidence` is deliberately not (ADR-016).

**CI jobs** (`.github/workflows/ci.yml`, 9 jobs): `build-test`, `proto`, `schema`,
`lint`, `security`, `licences`, `config`, `web`, `corpus`. `make ci-parity`
asserts every target in the `ci` line actually runs in the workflow.

**Local gates** (`make ci`, beyond the Actions set):
- `migrate-verify` — up, full-down, up again on a throwaway DB.
- `rls-test` — tenant isolation proven as `cvap_app` (no BYPASSRLS/SUPERUSER):
  reads, unset-context failure, cross-tenant writes, composite FK.
- `store-test`, `e2e` — DB-backed and two-process suites.
- `loadtest` — 10k assets; coarse ceiling always, precise §5 SLO with
  `CVAP_RUN_LOADTEST=1`.
- `mutate` — ~80 declared guard-reachability cases across the Go suites; the last
  full run killed all mutations. Every security-relevant guard has a mutation that
  proves its test actually reaches it.
- `safety` — §6.3 scope enforcement: engine egress capture + runtime send-path.
- `corpus-check` — §6.2: the label half always, the six accuracy gates when the
  lab is up (fatal in CI via `CVAP_REQUIRE_LAB=1`).

**Fault matrix** (§6.4): F1, F1a, F1b, F2, F3, F4, F5, F6, F6a, F6b — each
sabotaged.

---

## 4. Position against execution-plan §2 (MVP)

§2 is now **functionally complete and deployable** — the live single-node deploy
proves the whole path from enrollment through a real lab scan to findings on the
UI. What remains is a defined backlog (see `phase-3-backlog.md`), not open
scaffolding. The gaps, stated honestly:

| §2 area | State | Gap |
|---------|-------|-----|
| Control plane: RLS multi-tenant, local+OIDC auth, RBAC, asset/observation, scan/job/task, policy engine | ✅ | — |
| Control plane: **audit log** | ⚠️ partial | Table + writes exist for CLI privileged ops (bootstrap, enroll-token, tenant set-domain). No API route, no UI surface, not wired across all API mutations. |
| Scan point: enrollment, mTLS bidi, lease/epoch, capability handshake, chunked idempotent submission | ✅ | — |
| Scan point: **local durability** across SIGKILL | ⚠️ scheduled | ADR-026 durability is scheduled, not built (backlog). |
| Discovery engine: ARP/ICMP/TCP, connect+SYN, top-ports, banner, ~30 fingerprints, adaptive rate | ✅ | — |
| Asset resolution: ranked identity keys, merge evidence, time-bounded addresses | ✅ | — |
| Findings: ~20 non-CVE rules | ⚠️ partial | Engine + first rules shipped; **4 rules deferred** (S15). |
| UI: inventory, scan create/status, findings+evidence, exposure by zone, scan-point health | ✅ | `internet_reachable` exposure signal unwritten; `expected_ack_count` unpopulated; no audit view. |

Everything out of scope in §2 (CVE matching, advisories, credentialed, DAST, API,
SAST, cloud, containers, agents, reporting, k8s, HA) remains out of scope. Phase 3
begins to take on the first of these — the knowledge pipeline and CVE matching —
per ADR-059.

---

## 5. Failure patterns — the section that matters most

These have found more defects than any single technique, and until now they lived
only in agent memory where no person could read them. Each is a shape a green
build can hide. The unifying rule: **a passing test, a satisfied ADR, or a true
sentence proves less than it appears to — confirm against the thing that actually
fails, by running it, not by reading it.**

### 5.1 ADR-satisfied-at-the-wrong-layer

A control can be correct — it checks what it says, its test passes, its mutation
is killed — and still verify a proxy the code controls instead of the thing that
actually fails. The requirement is honoured one layer below where the failure
lives.

- **F9 (first instance):** both ADRs governing result submission were honoured *at
  the submission layer* (ADR-026 "results are always submitted"), but the process
  exited before the goroutine that did the submitting ever ran. The guarantee was
  true one layer above where the loss happened.
- **Second instance (S23):** bootstrap gained a self-verification — after creating
  the tenant it resolved the domain, found the user, verified the credential. It
  resolved *the domain bootstrap itself wrote* (`localhost`, the default), so it
  passed every time the real bug occurred: the operator reaches the box at an IP,
  not `localhost`. It answered "did I write a consistent record?" when the
  question was "can the operator log in?" The fix was not a better check but
  removing the guessable input — `--domain` is now required, so the value checked
  is the value used.

**Guard:** when adding a verification, ask whether it checks the thing that fails
or a proxy the code supplied. If the input is a default or a value the code just
wrote, the check is probably self-confirming. Force the real input.

### 5.2 Two-writers-one-fact

One fact derived by two code paths that were each correct in isolation and
disagreed with each other. The exposure count: `finding_exposure` (one row per
zone a finding is exposed in) and the zone rollup disagreed, because each computed
"how exposed is this" from a different write path and neither was wrong on its own
terms. The number a user saw depended on which path answered.

**Guard:** when a fact is displayed in two places, assert the two derivations
against each other in a test, not just each against its own expectation. A single
fact should have a single authority; if two paths must exist, one is the source
and the other is tested to match it.

### 5.3 Content-agnostic test suites

A suite that asserts *properties of* content but never the *presence of* content.
The fingerprint-corpus tests checked that every pattern compiles, every probe is
bounded, and the static policy rejects nothing — all of which passed identically
against the ten-entry corpus a session wrote and the two-entry corpus a stray `git
checkout` reverted it to. The revert was invisible through a green `make ci`,
every mutation killed, and a passing safety gate. A subagent found it by running
the shipped binary and noticing the TLS path was unreachable.

**Guard:** a session that ships content — rules, probes, corpus entries, fixtures —
needs at least one test that *names what the content must contain*. Without it,
losing the content is indistinguishable from having it. And never `git checkout` a
file with uncommitted work to restore a sabotage; reverse the exact edit and
verify the restore against a symbol only the new content has.

### 5.4 Documented-limitation-becomes-a-bypass

A limitation that was accurately documented, deliberately chosen, and harmless —
until a new capability made it reachable. `internal/scope` matched hostname rules
by string equality and said so plainly: "a hostname rule does not cover the
address that name resolves to." True and harmless for six sessions, *because
nothing in the tree could resolve a name or open a socket*. The discovery engine
landed, `net.Dialer` resolved the target and connected, and that paragraph became
a live scope bypass — allow a name, exclude its address, and packets reach the
excluded host.

**Guard:** before auditing a change that adds a capability (opening a socket,
resolving a name, spawning a process, writing a file), grep the tree for recorded
limitations — "does not cover", "deliberately not", "harmless because", "for as
long as" — and read each against the new capability. Ask: is this still harmless
now?

### 5.5 The presence assertion — needed a third time, so make it structural

A test can assert everything about *how content behaves* and nothing about
*whether the content is there, and whole*. §5.3 is one face of this; the sharper
observation is that the corpus has now needed a presence assertion **three separate
times**, each time fixed as its own instance:

1. **The reverted probe corpus.** A stray `git checkout` cut a ten-entry corpus to
   two, and every property test passed identically (§5.3, `restore-after-sabotage`).
   Fixed with a test naming what the corpus must contain.
2. **The empty-evidence rules.** Rules present in the pack whose evidence
   requirements were empty — findings that named no evidence a human could verify —
   passed every "the rule fires" test, because firing and being verifiable are
   different properties. Fixed by asserting the evidence was non-empty.
3. **The unreachable-rule denominator (S23).** The corpus gate cannot tell "rule
   found nothing" from "rule cannot run here," so a rule set that is ~31%
   unreachable reports the same FP/FN as one where everything works — a true number
   over an unstated denominator (backlog #14). The fix is not another per-instance
   test but a **manifest**: every rule in the registry declares one of EXERCISED /
   NOT_PRESENT / UNREACHABLE, a rule added without an entry fails the build, and the
   pass line reports the split so the denominator is stated.

**Why it is its own pattern:** the first two were fixed one instance at a time,
each with a bespoke "name what must be present" test. The recurrence is the signal.
A property test says what content *does*; only a presence assertion tied to the
registry says that content — and every category of it, including what is honestly
absent — is *accounted for*. The third time a class of gap recurs, the fix is
structural (fail the build on a missing entry), not another instance patch.

**How to apply:** when a suite reports a rate, a count, or a pass over content
drawn from a registry (rules, probes, corpus entries, migrations), make the
registry membership drive a manifest the build checks for completeness, and report
the denominator alongside the rate. A rate whose denominator is not printed is a
rate whose denominator will drift unnoticed.

### 5.6 A field written, carried, stored, and read by nobody

A field the producer sets, the wire carries, the database stores — and no consumer
ever reads. It is not dead code (it is written, so a compiler and an unused-var
linter both see it live) and not a wrong value (the value is fine); it is **data
with no reader**, which looks identical to working data until something depends on
it. Four instances in CVAP:

1. **`Kind`** — a job/probe kind set and carried but never branched on.
2. **The ICMP path** — a discovery code path present and reachable but producing
   nothing any consumer used.
3. **`internal_reachable`** — the authoritative exposure column written nowhere and
   read by a path that answered from `zone_type` instead ([[two-writers-one-fact]],
   §5.2 — the same defect seen from the write side).
4. **`osHint` (S24) — the one that blocked a phase.** The fingerprint engine
   produces an OS hint, it is serialized, stored in the observation payload, and
   read by no derivation: the asset's `os_family` stays `null` even when the hint
   exists. Because nobody reads it, P3.3's entry condition — which needs the OS on
   the asset — fails, and the failure was invisible until measured against a real
   host (ADR-060).

**Why it is its own pattern:** every layer looks correct in isolation — the field
is set, tagged, transmitted, persisted — so every single-layer test passes. The
defect lives in the *absence* of a consumer, which no layer's own test can see.

**How to apply — and the limit of the cheap check.** The reflection test that
caught `osHint`'s missing JSON tags asserts the *producer* side: a field present in
the struct is serializable. Extending it to the *consumer* side — "a field present
in the payload that no code path reads" — **is not tractable as a reflection test**,
and the reason is worth stating so it is not attempted as one: the read happens in a
different component, across a serialization boundary, out of a dynamically-typed
`jsonb` payload. Reflection sees the struct's shape, not who consumes the decoded
value one process away, and a `jsonb` read is not a struct-field access any static
pass can attribute. The tractable form is not static but **end-to-end**: for each
field a producer emits, an integration test that feeds an observation carrying it
and asserts the derived asset or finding *surfaces* it — the §5.5 presence assertion
applied to fields rather than to corpus entries. That would have caught `osHint`:
"a fingerprint OS hint produces a non-null `os_family`" is a one-case test, and it
fails today.

---

## 6. Standing requirement (from S23 onward)

Every session that lands a feature reports whether it needs a dashboard surface,
and if so whether that surface **exists / is deferred / is not needed** — and where
one is needed, **it lands in the same session as the feature**, not in a batch at a
phase boundary. Deferral is allowed only where a surface genuinely cannot land
then, and only as a named backlog item with an unblocker. This keeps the dashboard
continuously current rather than periodically caught up; `internet_reachable` and
`expected_ack_count` — built, correct, invisible for twenty sessions — are what
"later" produces. The checklist, the continuously-current rule, and the
retrospective gap list live in `phase-3-backlog.md`.
