# CyberSentinel — Execution Plan

**Context:** Implementation by Claude Code, driven by one person. Stated target: sellable in 2 months.
**Companion documents:** `cybersentinel-architecture-v2.md` (architecture), `erd.mermaid`, `scan-flow.mermaid`, `architecture.mermaid`.

---

## 1. Scope reset

### 1.1 What Claude Code genuinely compresses

The compression is real and large. Schema and migrations, CRUD APIs, RBAC scaffolding, gRPC service plumbing, job queue mechanics, mTLS enrollment flows, React dashboards, test harnesses, protocol implementations. This is boilerplate-heavy, well-patterned work where a competent team would spend three to four months on Phase 1 and you can plausibly spend three to four weeks.

Take that seriously when reading the estimates below. They are much more aggressive than the team-based numbers in the v2 roadmap.

### 1.2 What it does not compress

**Wall-clock validation against real networks.** A discovery engine that works against your lab will behave differently against a real /16 where a firewall silently drops SYNs to certain ranges, a load balancer answers for addresses nothing is listening on, and an old switch stops responding under load. You find these by scanning real networks repeatedly over weeks. No amount of code generation shortens that loop.

**Detection content curation.** The advisory ingestion pipeline is a day or two of code. Determining that your matcher produces a 3% false positive rate rather than 30% requires a labelled corpus, real hosts across several distro releases, and iteration. This is the actual product and it is judgment work against messy data.

**The fingerprint corpus.** Signatures come from real banners emitted by real devices. You cannot generate them.

**Anything needing an environment.** Credentialed Windows assessment needs a domain. Multi-vantage-point scanning needs at least two real network segments with a firewall between them. Lease and partition behaviour needs a way to actually partition things.

**Legal, compliance, and customer trust.** Zero lines of code.

### 1.3 The review gap

One person plus an AI, shipping a security product that holds customer credentials and a map of their weaknesses. The code will be written faster than any one person can meaningfully review it. This is manageable but it has to be named: budget for an external security review before the first customer touches it, put static analysis and dependency scanning in CI from week one, and keep the threat model current per subsystem rather than as a one-off document.

### 1.4 Honest estimates for this setup

| Milestone | Realistic |
|---|---|
| Core platform + scan point protocol (Phase 1) | 3–4 weeks |
| Discovery, fingerprinting, asset resolution — code | 4–5 weeks |
| Discovery accuracy acceptable on real networks | +2–3 months wall clock |
| Knowledge plane — code | 2–3 weeks |
| Knowledge plane — validated to usable FP rate | +6–10 weeks curation |
| Credentialed assessment (needs lab: domain + 3 distros) | 3–4 weeks |
| **First findings a customer would trust** | **5–7 months** |
| **Sellable to an enterprise buyer** | **8–12 months**, assuming design partner feedback throughout |

### 1.5 What two months actually buys

Eight focused weeks with Claude Code gets you a working **exposure scanner**: multi-tenant control plane, one scan point type over mTLS with the full lease protocol, network discovery and service fingerprinting, asset inventory with identity resolution, and roughly twenty high-confidence findings that need no CVE data at all.

That last part is the key move. TLS and certificate checks, plaintext protocol exposure, and exposed admin interfaces are self-contained, produce genuinely useful findings, and require none of the knowledge plane. It turns the eight-week deliverable from "an asset inventory" into "a security product that finds real problems," which is demoable, dogfoodable, and credible in a design partner conversation.

What it is not: a vulnerability scanner. No CVEs, no credentialed assessment, no DAST, no risk scoring. Do not claim otherwise in front of a buyer. A single wrong CVE claim in a first report ends the relationship, and in this market the reputational damage does not stay local.

### 1.6 Recommended commercial posture

Use the eight-week build to sign one or two **design partners** at heavy discount or free, in exchange for network access and feedback. That gives you the real-network validation loop that is otherwise your critical path, and it converts your weakest position — an unproven scanner — into your strongest asset — a scanner tuned against real environments before anyone pays list price.

If the two-month date is driven by a demo, a fundraise, or an internal commitment rather than actual revenue, say so and the plan gets easier. A demo in eight weeks is comfortable.

---

## 2. MVP definition

Fixed scope. Changes to this list are the primary risk to the date.

### In scope

**Control plane.** Multi-tenant with RLS, single-tenant by config. Auth (local + OIDC). RBAC with three roles. Asset and observation model. Scan / Job / Task decomposition. Policy engine with allowlist, exclusion, rate limits, time windows. Audit log.

**Scan point.** One type (internal/general). Token enrollment to client certificate. Outbound gRPC bidirectional stream over mTLS. Lease protocol with fencing epochs. Capability handshake. Chunked idempotent result submission with local durability.

**Discovery engine.** ARP, ICMP and TCP host discovery. TCP connect and SYN scanning. Top-1000 ports plus configurable. Banner grabbing. Service fingerprinting for ~30 common services. Adaptive rate limiting with fragile-device guard.

**Asset resolution.** Ranked identity keys with merge evidence. Time-bounded addresses. Service and software component derivation.

**Findings — no CVE data required.** Target ~20 rules: expired and near-expiry certificates, self-signed certificates on non-dev assets, TLS 1.0/1.1 enabled, weak cipher suites, missing certificate chain, plaintext protocols exposed (telnet, FTP, HTTP without redirect, SNMP v1/v2c with default community), exposed management interfaces (SSH/RDP/WinRM/database ports reachable from an untrusted zone), default credentials against a short curated list for common admin panels, directory listing enabled, missing security headers.

**UI.** Asset inventory with search and filter. Scan creation and status. Finding list with evidence. Basic exposure view by zone. Scan point health.

### Explicitly out of scope

CVE matching. Vendor advisory ingestion. Credentialed host assessment. Risk scoring beyond severity. DAST and crawling. API security testing. SAST. Cloud and container. Endpoint agents. Multi-vantage-point correlation beyond recording the zone. Reporting engine (CSV export only). Kubernetes. HA. SIEM integration.

---

## 3. Eight-week plan

Each week ends with something running. No week is pure scaffolding.

**Week 1 — Contracts and foundation.**
Write the Phase 0 artifacts in §4 before any feature code: ADR index, protocol contract, schema migrations. Repo structure with module boundaries and a `CLAUDE.md` per module. CI with build, test, `govulncheck`, `gosec`, dependency licence scan. Postgres with RLS policies and the full v2 schema migrated. Deliverable: `docker compose up` gives an empty but correct system, CI green.

**Week 2 — Control plane core.**
Auth, RBAC, tenant management, asset and observation models with the resolution algorithm, policy engine with scope validation. REST API with OpenAPI generated from code. Deliverable: create a tenant, a zone, a policy; API rejects an out-of-scope target.

**Week 3 — Scan point protocol.**
Enrollment token to certificate flow. gRPC bidi stream. Capability and version handshake. Lease grant, renewal, expiry, fencing epoch. Job dispatch via Postgres `SKIP LOCKED`. Deliverable: a scan point in a second container enrolls, receives a no-op job, submits a result, and correctly self-aborts when the lease is severed.

**Week 4 — Discovery engine.**
Host discovery across ARP, ICMP, TCP. Port scanning, connect and SYN. Adaptive rate limiting. Task chunking so a /24 spreads across jobs. Deliverable: scan a lab /24 and see hosts and ports in the database.

**Week 5 — Fingerprinting and asset resolution.**
Banner grabbing, service identification for the common set, OS guessing with explicit low confidence. Identity key extraction and the merge algorithm with evidence. Time-bounded addresses. Deliverable: scan the lab twice with a DHCP change in between and get one asset, not two.

**Week 6 — Findings.**
Rule engine with the core-side execution path. The ~20 non-CVE rules. Evidence capture to object store. Dedup keys, finding lifecycle, exposure records. Deliverable: findings with evidence a human can verify by hand.

**Week 7 — UI.**
Asset inventory, scan management, finding list with evidence detail, scan point health, CSV export. Deliverable: a person who did not build it can run a scan and read the results.

**Week 8 — Hardening and lab.**
The test suite in §6, especially the scope-enforcement gate. Load test to 10,000 assets. Partition and lease race tests. Installer and documentation. Deliverable: a build you would put on someone else's network.

**Buffer.** There is none. If week 4 or 5 slips, cut the default-credential rules and the OS guessing first, then the exposure view.

---

## 4. Phase 0 artifacts (Week 1)

### 4.1 ADR index

Record each as a short file in `docs/adr/`. Decisions are already made in the v2 architecture; the ADR captures context and consequences so Claude Code has a stable reference and so future-you knows what was rejected.

| # | Decision |
|---|---|
| 001 | Go for core, scan points and agents; Python for knowledge pipelines |
| 002 | PostgreSQL as system of record; RLS enforces tenancy |
| 003 | Job dispatch via Postgres `SKIP LOCKED`; broker deferred |
| 004 | Broker never exposed; dispatch service fronts it |
| 005 | Scan point transport is outbound-only gRPC bidi over mTLS |
| 006 | Observation-first: scan points never write assets or findings |
| 007 | Asset identity by ranked keys with retained merge evidence |
| 008 | Zone is a property of observations; exposure is derived |
| 009 | Rule / VulnerabilityDef / VendorAdvisory are separate entities |
| 010 | Finding dedup keys are source-specific; SAST keys on symbol not line |
| 011 | Scan / Job / Task three-level decomposition |
| 012 | Job leases carry monotonic fencing epochs; `reassign_safe` gates retry |
| 013 | Detection split: request-coupled at scan point, evidence-based at core |
| 014 | Vendor advisories are authority for packages; CPE is flagged fallback |
| 015 | Large evidence to object store; summary in Postgres |
| 016 | Observations partitioned monthly, 90-day default retention |
| 017 | Tenant-aware always, single-tenant by configuration |
| 018 | PKI trust anchor is configuration, not assumption |
| 019 | Rule packs are signed; offline import supported |
| 020 | Credentials just-in-time, scoped, memory-only on scan points |
| 021 | Safe mode default; detection without impact |
| 022 | Protocol versioning is additive-only within a major version |
| 023 | Compose first; Kubernetes deferred to Phase 12 |

### 4.2 Protocol contract

Write this before implementing either side.

```protobuf
syntax = "proto3";
package cybersentinel.scanpoint.v1;

service Enrollment {
  // One-time. Token exchanged for a client certificate.
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
  rpc RotateCertificate(RotateRequest) returns (EnrollResponse);
}

service Dispatch {
  // Long-lived bidirectional stream. Scan point always initiates.
  rpc Connect(stream ScanPointMessage) returns (stream CoreMessage);
}

service Ingest {
  // Client-streaming, chunked, idempotent by submission_id.
  rpc SubmitResults(stream ResultChunk) returns (SubmitAck);
}

message ScanPointMessage {
  oneof msg {
    Hello          hello           = 1;
    Heartbeat      heartbeat       = 2;
    LeaseRenewal   lease_renewal   = 3;
    JobProgress    progress        = 4;
    JobTerminal    terminal        = 5;
    Backpressure   backpressure    = 6;
  }
}

message CoreMessage {
  oneof msg {
    JobAssignment    job          = 1;
    LeaseGrant       lease        = 2;
    CancelJob        cancel       = 3;
    RulePackUpdate   rule_pack    = 4;
    CredentialGrant  credential   = 5;
    KillSwitch       kill         = 6;
  }
}

message Hello {
  string scan_point_id     = 1;
  string protocol_version  = 2;   // additive-only within major
  string agent_version     = 3;
  repeated Capability capabilities = 4;
}

message Capability {
  string engine         = 1;      // discovery | host | dast | api | cloud | sast
  string engine_version = 2;
  bool   enabled        = 3;
}

message JobAssignment {
  string job_id        = 1;
  string engine        = 2;
  int64  lease_epoch   = 3;       // fencing token, monotonic
  int64  lease_expires_unix = 4;
  bool   reassign_safe = 5;
  ScanConstraints constraints = 6;
  repeated Task tasks  = 7;
}

message ScanConstraints {
  uint32 max_rate_pps        = 1;
  uint32 max_rate_per_target = 2;
  string safety_mode         = 3;  // safe | intrusive
  repeated string exclusions = 4;  // enforced again scan-point side
  int64  window_ends_unix    = 5;
}

message CredentialGrant {
  string grant_id       = 1;
  string job_id         = 2;
  int64  expires_unix   = 3;      // short TTL
  bytes  material       = 4;      // memory only, zeroise on completion
  repeated string scope = 5;      // targets this may be used against
}

message ResultChunk {
  string submission_id  = 1;      // idempotency key
  string job_id         = 2;
  int64  lease_epoch    = 3;      // rejected if superseded
  uint32 chunk_index    = 4;
  bool   final          = 5;
  repeated Observation observations = 6;
}

message Observation {
  string observation_id   = 1;    // scan-point generated, stable across retry
  string task_id          = 2;
  string zone_id          = 3;    // vantage point
  string observation_type = 4;
  bytes  payload          = 5;    // JSON
  float  confidence       = 6;
  int64  observed_at_unix = 7;
}
```

Non-obvious requirements to encode in the implementation:

- `observation_id` is generated at the scan point and stable across retries, so a duplicated submission deduplicates cleanly.
- Exclusions are enforced at the scan point as well as at Core. Defence in depth on scope is the one place duplication is correct.
- On lease renewal failure the scan point aborts, zeroises credential material, and discards partial results from non-`reassign_safe` jobs.
- `Backpressure` is scan-point-initiated when its local buffer grows, and Core-initiated via a field on `SubmitAck` when ingest is saturated.

### 4.3 Schema

Generate migrations directly from the v2 ERD. Every tenant-scoped table gets the RLS policy in the same migration that creates it, never a follow-up. `OBSERVATION` and `EVIDENCE` are created as partitioned tables from day one — retrofitting partitioning onto a populated table is painful.

---

## 5. Non-functional requirements and SLOs

Calibrated to the MVP, not the enterprise vision. Revisit at Phase 4.

### Capacity

| Metric | MVP target |
|---|---|
| Assets per tenant | 10,000 |
| Tenants per Core | 50 |
| Scan points per tenant | 10 |
| Concurrent running scans per Core | 10 |
| Observations retained | 90 days |
| Findings retained | Indefinite |

### Performance

| Operation | Target |
|---|---|
| /24 host discovery + top-1000 ports, one scan point | < 10 min |
| /16 host discovery only | < 30 min |
| Asset list API, p95, 10k assets | < 300 ms |
| Finding list API, p95, 50k findings | < 500 ms |
| Result ingest throughput | 5,000 observations/sec |
| Scan point RSS ceiling | 512 MB |
| Scan point idle CPU | < 1% |

### Scanning safety limits

| Limit | Default | Policy may |
|---|---|---|
| Rate per scan point | 1,000 pps | lower only |
| Rate per target host | 50 pps | lower only |
| Rate against `fragile` assets | 10 pps | lower only |
| Connection timeout | 3 s | adjust |
| Concurrent connections per target | 20 | lower only |

### Reliability

| Metric | Target |
|---|---|
| Lease TTL / renewal interval | 60 s / 20 s |
| Heartbeat interval / timeout | 30 s / 90 s |
| Scan point offline buffer | 500 MB, 24 h |
| Control plane availability (SaaS) | 99.5% MVP, 99.9% GA |
| RPO / RTO | 24 h / 4 h MVP |
| Max result submission chunk | 4 MB |

### Security

Credential material never written to disk on a scan point. Certificate lifetime 90 days with rotation at 60. Audit events for every credential release, scope change, policy edit and scan start. Kill switch propagates to all scan points within 10 seconds.

---

## 6. Test and quality strategy

For a scanner, "finds the right things and not the wrong things" is the product. Measurement is not optional.

### 6.1 The lab

Stand this up in week 1, not week 8. It is the single highest-leverage investment in the plan.

- **Containerised vulnerable targets.** A compose file of deliberately outdated and misconfigured services: old nginx and Apache, exposed Redis and Mongo without auth, telnet, FTP, SNMP v2c with public community, expired and self-signed TLS, weak cipher configurations.
- **OS VMs.** Ubuntu 20.04 and 22.04, RHEL-compatible 8 and 9, Debian 12, Windows Server. Needed properly at Phase 4; stand up two now.
- **Network shape.** At minimum two segments with a firewall between them, so multi-vantage-point behaviour is testable rather than theoretical.
- **Fragile device simulation.** A service that degrades and stops responding above a request rate, to prove the adaptive limiter works.

### 6.2 Golden corpus

Hand-label the expected result for every lab target: which hosts, which ports, which services and versions, which findings. Every discovery run in CI diffs against it.

Track as CI metrics with failing thresholds:

| Metric | MVP gate |
|---|---|
| Host discovery recall | ≥ 99% |
| Port discovery recall, top-1000 | ≥ 98% |
| Service identification accuracy | ≥ 90% |
| Finding false positive rate | ≤ 2% |
| Finding false negative rate | ≤ 5% |
| Asset merge correctness | 100% on labelled scenarios |

Precision matters more than recall at this stage. A missed finding is a gap; a false finding is a lost customer.

### 6.3 The scope-enforcement gate

Treat this as the most important test in the suite. Run scans in a network namespace with packet capture on the egress interface and **assert that no packet ever leaves toward an address outside the configured scope**. Cover: exclusion overlapping an allow, CIDR boundary arithmetic, hostname resolving to an out-of-scope IP, redirect to an out-of-scope host, IPv6 forms of excluded IPv4 addresses, and scope changed mid-scan.

A scanner that touches something it was not authorised to touch is a legal problem, not a bug. This gate blocks merge.

### 6.4 Distributed behaviour

Use fault injection (toxiproxy or equivalent) for: lease expiry while the job is mid-execution; network partition then heal with a superseded epoch; duplicate result submission; Core saturation triggering backpressure; scan point restart with a buffered result set; clock skew between Core and scan point.

Each needs an explicit assertion, and the epoch rejection path needs a test that proves two scan points cannot both complete the same non-`reassign_safe` job.

### 6.5 Deferred but planned

Version comparator property tests against the public dpkg and rpm test vectors — required before Phase 3 ships. DAST crawler coverage scoring against a benchmark application — required before Phase 7. Neither belongs in the eight weeks.

### 6.6 Practical note on AI-generated code at this scale

Codebase coherence across many sessions is a real failure mode. Mitigations that work: keep module boundaries hard and interfaces explicit so any one module fits comfortably in context; maintain a `CLAUDE.md` per module stating its contract and invariants; require generated code to arrive with tests; and re-read the ADR index at the start of any session touching a cross-cutting concern. Drift shows up first as two modules disagreeing about a data contract, so contract tests between modules are worth more here than they would be with a human team.

---

## 7. Path from MVP to sellable

| Months | Work | Unlocks |
|---|---|---|
| 3–4 | Knowledge plane: NVD, vendor advisories, KEV, EPSS, version comparators | CVE claims become defensible |
| 4–5 | Credentialed host assessment, SSH and WinRM | High-precision findings, the real product |
| 5 | Risk engine v1 | Prioritised backlog rather than a list |
| 6 | Unauthenticated network rules, calibrated against credentialed truth | Coverage without credentials |
| 6–7 | Reporting engine, second scan point type, multi-vantage correlation | Enterprise-shaped deliverables |
| 7–8 | External security review, SOC 2 readiness, legal framework | Procurement-ready |

Start SOC 2 readiness and the authorization framework at month 4, not month 8. Both have lead times that will otherwise become the critical path.

---

## 8. Risk register

| # | Risk | Impact | Mitigation | Trigger to act |
|---|---|---|---|---|
| 1 | Scope creep against the fixed MVP | Date slips, nothing ships | §2 list is frozen; changes require cutting something | Any addition proposed |
| 2 | Product sold or demoed as a vulnerability scanner before CVE data exists | One bad report ends the account and the reference | Explicit positioning as exposure scanning until month 4 | First customer conversation |
| 3 | Discovery accuracy poor on real networks | Core capability untrusted | Design partner network access from week 6 | Lab-only validation at week 8 |
| 4 | Single-person review of AI-generated security code | Vulnerability in the security product | CI static analysis, external review before first customer | Before any external deployment |
| 5 | Knowledge plane has no long-term owner | Content staleness, silent accuracy decay | Name an owner or budget for the data work before month 3 | Month 3 |
| 6 | No scanning authorization framework | Legal exposure, potentially criminal | Contract template and `authorization_verified` enforcement before any non-owned target | Before first external scan |
| 7 | Codebase coherence loss across sessions | Rework, contract drift | Module boundaries, per-module `CLAUDE.md`, contract tests | Two modules disagree on a contract |
| 8 | Scanner damages a customer system | Reputational, contractual | Rate limits, fragile-device guard, kill switch, safe mode default, liability terms | Before first external scan |
| 9 | GPL or AGPL dependency shipped on-prem | Licence contamination on a commercial binary | Licence scan in CI from week 1 | Any new dependency |
| 10 | Two-month date is externally committed | Pressure to ship something unsafe | Renegotiate against §1.5 scope now | Immediately |

---

## 9. What still needs a human

No amount of implementation velocity removes these, and none of them are on the eight-week critical path by accident — they are simply not code.

Design partner relationships and the network access they bring. Detection content curation and the judgment about confidence thresholds. Fingerprint signatures from real devices. The customer authorization contract and liability terms. SOC 2 evidence collection. External security review. Pricing. And the decision about when the product is good enough to charge for, which is the one call that most determines whether this succeeds.
