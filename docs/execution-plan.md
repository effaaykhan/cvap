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

Write this before implementing either side. Frozen on ship: ADR-022 makes it additive-only
within a major version, so field numbers are never reused and semantics never change.

```protobuf
syntax = "proto3";
package cybersentinel.scanpoint.v1;

// Four services, all scan-point-initiated over the ADR-005 posture:
// outbound TLS 1.3, mutual auth, no inbound connection to a scan point, ever.

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
  // Bidirectional: per-chunk acks carry resumption points and backpressure.
  // A terminal-only ack cannot express either (ADR-026).
  rpc SubmitResults(stream ResultChunk) returns (stream SubmitAck);
}

service RulePacks {
  // Bulk transfer off the dispatch stream: a multi-MB bundle there would
  // head-of-line block job dispatch, which ADR-005 rejects.
  rpc FetchRulePack(FetchRequest) returns (stream RulePackChunk);
}

message ScanPointMessage {
  oneof msg {
    Hello           hello            = 1;
    Heartbeat       heartbeat        = 2;
    LeaseRenewal    lease_renewal    = 3;
    JobProgress     progress         = 4;
    JobTerminal     terminal         = 5;
    Backpressure    backpressure     = 6;
    KillAck         kill_ack         = 7;
    RulePackStatus  rule_pack_status = 8;
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
    ServerHello      server_hello = 7;
  }
}

message Hello {
  string scan_point_id     = 1;
  string protocol_version  = 2;   // additive-only within major
  string agent_version     = 3;
  repeated Capability capabilities = 4;
  repeated LoadedRulePack loaded_packs = 5;  // offline import means packs
                                             // arrive out-of-band (ADR-019)
}

message ServerHello {
  string accepted_protocol_version = 1;
  string min_supported_version     = 2;
  string deprecation_notice        = 3;  // operator-facing, not a bare status
}

message Capability {
  string engine              = 1;  // discovery | host | dast | api | cloud | sast
  string engine_version      = 2;
  bool   enabled             = 3;
  string rule_format_version = 4;  // Core dispatches no rule format this
                                   // scan point cannot execute (ADR-022)
}

message LoadedRulePack {
  string pack_id = 1;
  string version = 2;
}

message JobAssignment {
  string job_id        = 1;
  string engine        = 2;
  int64  lease_epoch   = 3;       // fencing token, monotonic
  int64  lease_expires_unix = 4;
  bool   reassign_safe = 5;       // governs retry, never retention (ADR-026)
  ScanConstraints constraints = 6;
  repeated Task tasks  = 7;
}

message Task {
  string task_id     = 1;
  string target      = 2;
  bool   fragile     = 3;  // Core-held asset attribute the scan point
                           // cannot derive; caps rate regardless of policy
}

message ScanConstraints {
  uint32 max_rate_pps            = 1;
  uint32 max_rate_per_target     = 2;
  string safety_mode             = 3;  // safe | intrusive
  repeated string exclusions     = 4;  // enforced again scan-point side
  int64  window_ends_unix        = 5;
  repeated string allowed_targets = 6; // allowlist; exclusions take precedence.
                                       // Without this the scan-point check
                                       // authorises anything not denied.
  uint32 fragile_rate_pps        = 7;
  uint32 max_concurrent_per_target = 8;
  uint32 connect_timeout_ms      = 9;
}

message CredentialGrant {
  string grant_id       = 1;
  string job_id         = 2;
  int64  expires_unix   = 3;      // short TTL
  bytes  material       = 4;      // memory only, zeroise on completion
  repeated string scope = 5;      // targets this may be used against
  CredKind cred_kind    = 6;      // never overload material
}

enum CredKind {
  CRED_KIND_UNSPECIFIED = 0;
  SESSION_HANDLE        = 1;
  KERBEROS_TICKET       = 2;
  SSH_CERT              = 3;
  DERIVED_TOKEN         = 4;
  RAW_SECRET            = 5;
}

message KillSwitch { string kill_id = 1; }

message KillAck {
  string kill_id      = 1;
  int64  acked_at_unix = 2;
  uint32 tasks_halted = 3;
}

message RulePackUpdate {
  // Notification only. Fetch via RulePacks.FetchRulePack.
  string pack_id          = 1;
  string version          = 2;
  string signature_digest = 3;
}

message RulePackStatus {
  string pack_id = 1;
  string version = 2;
  RulePackState state = 3;
  string detail  = 4;
}

enum RulePackState {
  RULE_PACK_STATE_UNSPECIFIED = 0;
  LOADED                      = 1;
  REJECTED_SIGNATURE          = 2;
  REJECTED_FORMAT             = 3;
  FETCH_FAILED                = 4;
}

message ResultChunk {
  string submission_id  = 1;      // idempotency key
  string job_id         = 2;
  int64  lease_epoch    = 3;      // quarantined if superseded, never dropped
  uint32 chunk_index    = 4;
  bool   final          = 5;
  repeated Observation observations = 6;
  bool   incomplete     = 7;      // on EVERY chunk: with resumption Core may
                                  // process chunks before it sees final
  TerminationReason termination_reason = 8;
}

enum TerminationReason {
  TERMINATION_REASON_UNSPECIFIED = 0;
  COMPLETED            = 1;
  LEASE_LOST           = 2;
  CANCELLED            = 3;
  KILLED               = 4;
  ENGINE_FAILURE       = 5;
  WINDOW_EXPIRED       = 6;
  SCOPE_VIOLATION_HALT = 7;
}

message SubmitAck {
  string submission_id       = 1;
  uint32 last_chunk_accepted = 2;  // resume point
  SubmitStatus status        = 3;
  uint32 retry_after_ms      = 4;  // Core-initiated backpressure
  string detail              = 5;
}

enum SubmitStatus {
  SUBMIT_STATUS_UNSPECIFIED = 0;
  ACCEPTED              = 1;  // processed normally
  ACCEPTED_QUARANTINED  = 2;  // stored, withheld from the finding pipeline,
                              // operator-surfaced. Stop retrying, clear buffer.
  REJECTED_DUPLICATE    = 3;  // submission_id already ingested. Clear, no retry.
  REJECTED_MALFORMED    = 4;  // unparseable, or unknown observation_type.
                              // Clear buffer, no retry, log locally.
  RETRY_LATER           = 5;  // transient Core-side failure. Keep buffer, back off.
}

message Observation {
  string observation_id   = 1;    // scan-point generated, stable across retry
  string task_id          = 2;
  string zone_id          = 3;    // vantage point
  string observation_type = 4;    // deliberately an open string, not an enum
  bytes  payload          = 5;    // JSON
  float  confidence       = 6;
  int64  observed_at_unix = 7;
}
```

Non-obvious requirements to encode in the implementation:

- `observation_id` is generated at the scan point and stable across retries, so a duplicated submission deduplicates cleanly.
- Exclusions **and the allowlist** are enforced at the scan point as well as at Core. Defence in depth on scope is the one place duplication is correct. Under ADR-027 this check lives in the scan point *runtime*, never in an engine: engines receive resolved, pre-authorised targets and send anything discovered mid-scan — a redirect, a DNS answer, a referenced host — back to the runtime for authorisation. Two enforcement sites, whatever the engine count or language.
- On lease renewal failure the scan point aborts, zeroises credential material, marks results incomplete, and submits them.
- `Backpressure` is scan-point-initiated when its local buffer grows, and Core-initiated via `SubmitAck.retry_after_ms` when ingest is saturated. Per-chunk acks are what make both the resumption point and the saturation signal arrive while the upload is still running.
- **A superseded lease epoch yields `ACCEPTED_QUARANTINED`, not a rejection.** The results are stored and withheld from the finding pipeline, never dropped — they are the record of what the job touched, which is the content of ADR-012's operator escalation. Only `REJECTED_DUPLICATE` and `REJECTED_MALFORMED` tell a scan point to clear its buffer without the data having been kept.
- `observation_type` is an **open string on the wire by design**: engines are extensible under ADR-027, and a closed wire enum would make every new observation type a proto change. The closed enum lives in the ERD. Core validates the incoming value against it at ingest and returns `REJECTED_MALFORMED` for an unknown type. Do not "tighten" field 4 to an enum later — that is the semantic change ADR-022 forbids.

### 4.3 Schema

Generate migrations directly from the v2 ERD. Every tenant-scoped table gets the RLS policy in the same migration that creates it, never a follow-up. `OBSERVATION` is created as a partitioned table from day one — retrofitting partitioning onto a populated table is painful. `EVIDENCE` is **not** partitioned (ADR-016): it is pruned by finding status rather than by time, so there is no partition key matching how it is actually dropped. Revisit at Phase 4 with measured row counts.

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

Defined in **ADR-024**, which is the authority. Not restated here — see
`docs/adr/024-scan-blast-radius-controls.md` for the table of platform defaults
(per-scan-point, per-target and `fragile` rate ceilings, connection timeout, concurrency cap
and kill switch propagation). Policies may lower these ceilings and may never raise them.

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

**Encrypted local result durability on the scan point (ADR-026).** The scan point buffers results in memory and submits with the full five-outcome retry semantics, but a restart loses whatever had not been uploaded. ADR-026 requires a scan point that finishes a two-hour job and cannot reach Core to persist to local **encrypted** storage and retry, and that is not implemented.

**Scheduled** now, moved off "deferred" — because session 20's fault matrix argued for it twice by measurement, which is enough evidence even though the unblocker below still gates *when*. F5 (`TestResumeRestartsFromLastAckedChunk`, and the graceful-shutdown fix that now submits what a job gathered on a clean SIGTERM) showed the buffer's retry-and-resume works while the process lives or exits cleanly: the mechanism is sound. F9 (the shutdown-drain finding) showed the other half — the buffer is *memory-only*, so a SIGKILL, a crash or an OOM kill loses whatever had not been delivered, with no graceful path able to catch it. That is precisely the case on-disk durability exists for, and the cancellation entry above measured it directly: zero observation bytes survived a SIGKILL. A mechanism proven to work exactly until the process is hard-killed is a mechanism whose gap is now concrete rather than theoretical.

Scheduled, not imminent, because the unblocker has not moved. The only key custody available on a scan point today is a key file sitting next to its ciphertext at `0600`, which protects a stolen backup or a captured disk image and nothing else — an attacker on the host reads both. Shipping it would let the ADR read as satisfied while the property it names does not hold, which is worse than the gap being visible.

Also deferred from the same session, all recorded in `.claude/agent-memory/scan-safety-auditor/scanpoint_runtime_bypasses.md`: the runtime does not yet stop at `ScanConstraints.window_ends_unix` (a MUST in `dispatch.proto`, and `WINDOW_EXPIRED` is produced by nothing); `safety_mode` reaches the runtime and dead-ends because the engine job contract has no field for it; and constraints are captured at claim time and never re-pushed, so a deny rule added mid-scan reaches no running engine. Two items from that list are now closed: translated IPv6 notations are handled by ADR-039, and the discarded normalised host by ADR-042.

**Open findings from the discovery session's packet-capture audit, deferred deliberately:**

The third — the rate budget counting connect attempts while ADR-024's ceilings are in packets — is FIXED rather than deferred. Amending the ADR to say "attempts" was the alternative and it is the wrong direction: the number that protects a device is packets it has to process, and a ceiling defined by whatever the implementation happened to count is not a ceiling. At 2.94 SYNs per attempt the 10 pps fragile cap was really about 29. The engine now charges a model of the SYN train and the handshake, the safety gate asserts the wire-to-charged ratio, and the lab gained a filtered host because without one that assertion could not fail.

- **A cancelled job records nothing about what it touched.** Coverage lives in `PortsScanned` on the host observation, emitted last; measured, nine seconds of scanning and 73 outbound packets produced **zero bytes** of observations on both SIGTERM and SIGKILL.

  Deferred to the finding pipeline, because it is the same question ADR-026's incomplete submissions already answer for lease loss: *what did we touch before we stopped*. Solving it here with a periodic partial-coverage row would be a second mechanism for one question, and the two would drift. The right shape is the one ADR-026 already has — a partial record marked incomplete, with a termination reason — applied to cancellation as well as to lease loss.

- **Safe mode holds every open port's connection for a full second.** `readBanner` waits up to a second for a banner that HTTP never volunteers, with no reduction for `fragile`.

  **Closed by ADR-048.** `bannerWait` is service-aware: a port whose protocol has the client speak first — HTTP, TLS, SMB, RDP, the databases — gets 250ms instead of a second, and `clientSpeaksFirst` is that port-to-behaviour table, built where the knowledge belongs. The trade is stated rather than hidden: a service volunteering a banner late, on a port where nothing normally volunteers, is missed; the probe chain covers that under an intrusive job and safe mode genuinely loses it. It remains in the discovery engine, whose `readBanner` still waits the full second — discovery's job is to find open ports, and it has no service knowledge to shorten the wait with.

**Deferred from the fingerprinting session (ADR-048), each with what unblocks it:**

- **`RulePacks.FetchRulePack` and the `RulePackUpdate` notification.** The pack format, signature verification and offline import of a local signed file all ship; the fetch half does not.

  **The unblocker is signing-key custody and rotation.** Every fetch path needs a scan point to decide which key to verify against — `RulePackChunk.signing_key_id` exists for exactly that — and there is nowhere to put a key set or a rotation policy today. Fetch without it means one hard-coded key forever, or a scan point that cannot survive a rotation. This is the same key-custody problem the encrypted result buffer and the OIDC client secret are both deferred on, and it should be solved once for all three. Offline import needs none of it, and ADR-019 calls that path required rather than optional.

- **Persisting `RulePackStatus`.** Core logs it, at warn for anything that is not `LOADED`. That meets ADR-019's "the refusal is not silent" and no more: it cannot be queried, alerted on, or shown beside the scan whose coverage it explains. Needs a table and a migration, which the fetch half needs too, so the two land together.

- **SNMP.** Named in the week 5 brief and absent from the corpus. SNMP is UDP-only in practice, discovery finds TCP ports only, and service identification runs against ports discovery found — so there is no UDP port to identify until there is UDP discovery. **The unblocker is UDP support in the discovery engine**, which is the same allowlist-widening argument as SYN and ARP below, minus `CAP_NET_RAW`. DNS ships over TCP/53.

- **The obsolete-TLS-version finding.** The `tls` payload records the version that was NEGOTIATED, which is the best both ends support and not the worst the server accepts: a server offering TLS 1.0 and 1.3 reports 1.3. Detecting the floor needs one handshake per version, which is a packet cost per port. Week 6 should decide whether that is worth the budget before it writes a rule that reads this field as though it were the floor.

- **Core does not tell the fingerprint engine which ports are open.** `ToEngine.Ports` exists and the runtime fills it; nothing plans a fingerprint job from discovery's observations, so the engine falls back to its own port list and re-establishes what discovery already knew. **The unblocker is week 5's second half** — observation to asset to plan. The cost until then is a duplicated connect per port, which is visible in the packet budget rather than hidden.

- **Per-target rate does not aggregate across concurrent jobs.** `internal/scanpoint/allocator.go`
  divides ADR-024's 1,000 pps per-SCAN-POINT ceiling between jobs. Nothing divides the 50/10 pps
  per-TARGET ceiling, so two jobs covering one host each receive the full allowance.

  **Measured**, not reasoned about: two concurrent engine processes against one fragile target,
  each handed exactly what `job.budget()` produces for a 10 pps fragile job — `mean 8.75 pps, max
  in any 1.0s window = 18`. Linear in job count, so three jobs is 27 and the ceiling that protects
  a delicate device is whatever Core happened to dispatch.

  It was theoretical while discovery was the only engine that could send a packet. It is concrete
  now: ADR-048's port fallback means **a fingerprint job re-scans ports a discovery job just
  found**, so the two cover the same host by design rather than by accident.

  **The likely fix is a claim predicate at Core**: `Jobs.Claim` declines to hand out a job whose
  targets overlap a job already running on the same host. That is the same shape as
  `allowed_zones` and the kill-switch scope — a condition inside the claim rather than a check
  after it — and `internal/dispatch/CLAUDE.md` records why that shape is the right one: a job
  claimed and then released increments `attempt` on every poll and hits `MaxAttempts` in seconds,
  so the protection destroys the scan it was written to protect.

  The alternative is a per-target bucket in the runtime, shared across engine processes. That is
  cross-process shared mutable rate state, which ADR-027 rejects between processes for reasons
  that have not weakened, so it is named here only to record that it was considered and refused.

  **This belongs wherever session 14 touches planning**, since asset identity resolution is what
  will start producing fingerprint jobs from discovery's observations — which is exactly the
  moment two jobs covering one host stops being hypothetical.

- **Four probes have never fired against a live server**: SMB, RDP, MSSQL and DNS. The lab has no target for any of them. Their payloads are the standard opening packet of each protocol, sent before authentication, and the static policy bounds them regardless of what their patterns do — but a rule nothing has exercised may silently match nothing, which is the failure this codebase keeps finding. **The unblocker is lab targets**, and it belongs with week 8's golden corpus.

**Deferred from the rule-engine session (ADR-050), each with what unblocks it:**

- **Four of the ~20 non-CVE rules do not ship**, and week 8's coverage claim must exclude them. "TLS 1.0/1.1 enabled" and "weak cipher enabled" ship in the narrower negotiated form (`tls.legacy_negotiated`, `tls.weak_cipher_negotiated`) — a version-ladder probe, one handshake per version, is the unblocker for the "enabled" form. "SNMP v1/v2c default community" needs UDP discovery. "Directory listing enabled" needs a bounded GET probe kind (the HTTP probe is HEAD by design). All four are named in ADR-050.

- **Two shipped HTTP rules read the sanitised evidence excerpt, not a structured field.** `http.no_https_redirect` and `http.missing_headers` parse a status line and headers out of prose, at 0.75 confidence. **The unblocker is a structured `http` object on the service payload** — status code and headers as a map — gathered by the fingerprint engine beside the `tls` object it already gathers. A latent limitation: true today, breaks when the excerpt format changes for an unrelated reason.

- **A predicate language for rules.** The engine hosts closed evaluators with content parameters (ADR-050). **The unblocker is concrete: the first rule needing logic no evaluator provides where adding one would be the third of the same shape** — the certificate-threshold evaluators are the ones to watch.

- **Retroactive re-evaluation over history.** `rules.Evaluate` is pure and takes `now` as a parameter specifically so a corrected rule can be replayed against stored observations (ADR-013). Nothing calls it that way yet. **The unblocker is a decision about what a re-evaluation does to findings an operator has already triaged** — reopening a `false_positive` because a rule changed is not obviously right — and it lands with signed rule-pack import.

- **The management-interface rule guesses no zone trust.** It treats `external`/`dmz` as untrusted and leaves `branch`/`cloud` out. **The unblocker is a per-zone trust attribute an operator sets** — `scan_zones.trust_level` exists as an integer with no assigned meaning.

**Surfaced by the golden corpus (session 16):**

- **`tls-weak-cipher-negotiated` is currently unfireable.** The rule ships, but the fingerprint TLS client offers only Go's *secure* cipher suites, so it never negotiates an insecure one — and a server offering *only* a weak suite cannot even be handshaked (measured: the client's handshake fails against nginx offering only `ECDHE-RSA-AES128-SHA256`). So the rule cannot receive the input it judges. **The unblocker is an engine change**: `inspectOnlyTLSConfig` must OFFER the weak suites, the same way it already offers old TLS versions via `MinVersion`, so a server that accepts one is detectable. Named in `lab/corpus/corpus.json` under `uncovered` and left for a fingerprint-engine session rather than worked around in the lab. The corpus found this — a rule that looked shipped was not exercisable.

- **The OS VMs of §6.1 are not stood up.** This environment has no hardware virtualisation (`/dev/kvm` absent), so the two OS VMs cannot run here. OS-family is covered only where a banner volunteers it (the OpenSSH suffix); real OS fingerprinting is Phase 4, which the plan already schedules. The lab is otherwise complete: 20 containerised targets across the two segments, each reproducing one labelled corpus case from its own definition.

**Deferred from the asset-resolution session (ADR-049), each with what unblocks it:**

- **A host with one moderate key does not merge across an address change.** ADR-007 needs one strong key or corroboration among weaker ones, and a lone SSH host key is uncorroborated. The common estate — Linux, SSH, no TLS — is exactly this case, and so is the lab's own SSH host.

  **The unblocker is a second independent key on those hosts.** `hostname_domain_os` is the candidate ADR-007 already names, and it is unreachable today for a stated reason: a certificate SAN gives a hostname the TARGET chose, and the OS hint is explicitly non-authoritative (ADR-048 §9), so composing them would build a moderate key out of two things this codebase says not to trust. Real OS fingerprinting is Phase 3. Asserted by `TestOneModerateKeyAloneDoesNotMergeAcrossAnAddressChange` so that loosening the rule is a decision rather than a drift.

- **`software_components` stays empty.** Nothing produces `package` observations: that needs credentialed assessment, which is out of MVP scope (§2). The table, the advisory-matching index and ADR-014's distro path all exist and are exercised by nothing. Named here rather than left as a table a reader assumes is populated.

- **The unresolved queue has no operator surface.** `asset_resolution_queue` is written by correlation and read by `PendingCount`. Adjudicating an item — choosing a candidate, declaring a new asset, discarding the evidence — is week 7's UI. Until then a conflict parks the observations unresolved, which is the correct direction and is not the same as being handled.

- **Correlation is per-observation-batch and does not re-run over history.** `domain.Resolve` is pure specifically so a corrected rule can be replayed against stored observations, and nothing calls it that way yet. **The unblocker is a decision about what replay does to existing assets** — re-deriving an inventory that findings already point at is not a background job, and it needs its own session.

**Deferred from the discovery session (ADR-047), and the line between them is one thing:**

- **SYN scanning, ARP discovery and ICMP echo.** §2 says "ARP, ICMP and TCP host discovery. TCP connect and SYN scanning"; what ships is TCP connect. Every deferred method needs a socket the Go standard library will not create — raw for SYN and ARP, an unprivileged `SOCK_DGRAM` ICMP socket for the third — and each would widen the engine import allowlist past the single `net` ADR-047 argues for. SYN and ARP additionally need `CAP_NET_RAW`, which changes how a scan point is **deployed**, not merely what it can do.

  **What unblocks it:** a decision on how a scan point acquires `CAP_NET_RAW`, recorded as its own ADR, plus an answer to how `make safety` proves a raw-socket engine stays in scope — the harder half, since the connect path is observable through the socket API and a raw sender is not.

  **What it costs meanwhile, stated rather than discovered:** connect completes the handshake, so it is louder against anything watching and slower against a filtered host; a fully filtered host is indistinguishable from an absent one; and a host that answers no TCP but does answer ping is not found at all.

- **The default port set is ~180, not the top 1000.** It covers every service the MVP's finding rules reason about. The full list is empirical frequency data belonging in a data file beside the fingerprint corpus rather than a literal in source — a data change, not a code change. A padded list that *looked* like the top 1000 would have made the gap invisible.

- **Service fingerprinting is banner capture, not identification.** §2's "~30 common services" is week 5. What ships records what a service volunteered, and under an intrusive job what a probe drew out, with provenance on both. Turning bytes into a service name is the next session's work.

**Deferred from the operator API session, and each is a decision rather than an omission:**

- **Back-channel logout is not implemented, so a session outlives disablement at the identity provider.** OIDC itself landed (ADR-046): authorization code with PKCE, subject-based identity, per-tenant issuer and audience checks. What is missing is `backchannel_logout_uri` — a user disabled at the IdP keeps a live CVAP session until it expires, at most twelve hours, and the only thing that ends it today is an administrator disabling the user here as well. Until that lands, disabling somebody is a two-place operation and the runbook has to say so.
- **An identity provider that requires a confidential client cannot be used.** No `client_secret` is stored anywhere, deliberately, because a per-tenant secret in a table is the same key-custody problem the encrypted buffer is deferred on — and it should be solved once for both.
- **Tenant, user and role management are not endpoints.** A tenant is created by a migration or by hand, and roles are written as JSON. Deferred deliberately in this session's scope split, because the interesting decisions in it — who may create a tenant, whether a role can grant a permission its creator lacks — deserve their own session rather than being answered incidentally.
- **Findings and asset read endpoints do not exist**, and neither does `internal/store/findings.go`. The observation-to-asset derivation is the work those endpoints read from, so they follow it.
- **Rate limiting is not implemented.** The architecture's API gateway box says "authN, rate limit, tenant resolution" and two of the three are done. Login is the endpoint that needs it most; the per-account lockout in `user_credentials` bounds guessing against one account and does nothing about a spray across many.
- **Scheduled and recurring scans do not exist.** A scan created through the API is planned by the sweeper's `PlanPending` pass on its next tick, so the path from creation to queued jobs is complete; what is missing is a scan that runs on a schedule without somebody creating it. `scan_policies.time_windows` already constrains WHEN a job may run, which is a different question from when a scan is created.

What unblocks it: a decision on key custody, recorded as an ADR. The candidates are a TPM-sealed key where hardware allows, a key derived from the enrollment private key with the resulting threat model stated honestly, or Core issuing a wrapping key at enrollment so a scan point that is revoked cannot decrypt its own backlog. Until then the buffer is bounded at `BufferHardBytes` and a full buffer **refuses new work rather than dropping observations** — the failure mode ADR-026 exists to prevent — reporting `BACKPRESSURE_STATE_HARD` so Core stops assigning.

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
