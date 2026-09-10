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
| Phase 2 — discovery, fingerprint, resolution, findings, UI, hardening | Weeks 4–8 | 12–23 | complete (closed S23) |
| Phase 2 validation — real-network accuracy | S24 | 24 | done; P3.3 entry condition measured & **failed** (ADR-060), then met by S26–S31 |
| Phase 3 — knowledge pipeline / CVE matching | §7 path-to-sellable | 25–37 | **COMPLETE (close-out S37).** P3.1 comparators (S27) ✅ · P3.2 advisory ingestion (S28) ✅ · P3.3 release resolution (S31) ✅ · B29 coverage window (S33) ✅ · P3.4 KEV/EPSS model + ingestion (S34) ✅ · advisory→finding path (S34b, ADR-070) ✅ · confidence by weakest link (S34c/d, ADR-072/073) ✅ · P3.4 ordering acceptance on real findings (S36) ✅ · #6 exposure resolved (S37, ADR-074) ✅ — the chain closes, produces real CVE-linked findings, and orders them by priority (see "What Phase 3 changed", §2). Ceiling is the banner-inferred package identity. Next: enterprise console (#12, designed S37); the Phase 4 credentialed-vs-widen decision (S38, `docs/phase-4-sequencing-decision.md`) is the operator's |
| Phase 4 — credentialed assessment | §7 path-to-sellable | (sequencing decision open, S38) | **Not started; sequencing under decision.** Three gaps (B30, B31, B33) converge on it. Recommendation: hold behind a named trigger, take the console + B28 first (`docs/phase-4-sequencing-decision.md`). Operator decides. |

Weeks and sessions are not one-to-one. The eight-week plan assumed a team; this
build is sequential under one operator with Claude Code, so a "week" of the plan
spans several sessions and the review load is heavier per feature (§1.3 of the
plan predicted exactly this).

### What P3.3 changed — the chain closed (S27–S31)

P3.3 did not add a feature to the product; it changed **what the product does**.
Through S23 the platform found non-CVE, rule-based issues on hosts it inventoried.
As of S31 it does vulnerability *matching*: a real host's observed service versions
resolve its distro **family** (B21) and **release** (ADR-064), and the release keys a
**backport-aware advisory match** (ADR-014) through the **dpkg/rpm comparators**
(ADR-062) against **ingested vendor advisories** (ADR-063) — producing a real,
CVE-backed finding. The acceptance is one real machine end to end: Metasploitable
→ `ubuntu 8.04 / hardy` → USN-1467-1 → **CVE-2012-2122 vulnerable** on its measured
MySQL. That is the join the whole of Phase 3 was sequenced toward, and it is why
what remains is bounding and widening the chain (coverage windows B29, service
identification B28, family correctness B24, rpm-in-situ B26), not building it.

**The chain's reach is honestly bounded, not silently assumed:** it resolves only
releases the keyspace covers and only services the corpus version-identifies
(5/11 on Metasploitable, ADR-065/B28), every failure mode is *unresolved/unmatched*
rather than a wrong answer, and the coverage window itself is a named gap (B29)
before P3.4 trusts the finding set.

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
- **S26 — P3.3 prerequisites: B21 (OS attribution) + B22 (safe-mode banner
  patterns)** (ADR-060/061). The buildable safe-mode half of P3.3's entry
  conditions. (The operator numbers the S24 validation as session 25; this is
  session 26 — a +1 offset from an uncounted session.)
  - **B21 — the osHint dead-read (§5.6) fixed end to end.** `domain.AttributeOS`
    (three-state model, reviewable precedence, provenance) → correlate reads the
    hint and writes it to the asset. Measured live on Metasploitable: the `.129`
    asset now carries `distro_family=debian, distro_release=null (family-only),
    confidence 0.95`, provenance `[ssh:22 → debian, contributed]`. Before this
    session it was null. **The family is WRONG (it is Ubuntu):** the SSH package
    string `Debian-8ubuntu1` matches the Debian pattern and the `8ubuntu1` suffix
    — plus `(Ubuntu)` in SMTP and `3ubuntu5` in MySQL — is ignored. Not tuned away
    this session; it is the clean follow-up (B24). Release correctly null — no
    fabrication.
  - **B22 — service identification on Metasploitable, recorded with the
    distinction the corpus gate exists to preserve.** Two numbers, and the second
    is NOT a claim about an unseen host:
    - **6/11 blind** — what the pre-session banner set identifies (vsftpd 2.3.4,
      OpenSSH 4.7p1, telnet, Postfix, ProFTPD 1.3.1, MySQL 5.0.51a).
    - **7/11 after this session's VNC pattern fired** (RFB greeting → vnc). The
      "8th", IRC, has a pattern that **did not match** this host's 6667 banner — a
      pattern *present* is not a pattern *exercised*, and recording it as 8 would
      erase exactly that difference (§5.5).
    - The other 4 (DNS, HTTP, SMB, PostgreSQL) are probe-gated — unreachable in
      safe mode by design, not a corpus gap.
    - **These are counts against ONE real host, with patterns that match it — a
      data point, not the generalizable service-ID accuracy the golden-corpus gate
      measures against labelled hosts.** The two must never be conflated.
    - **⟳ Corrected in S31 (measured, `TestMetasploitableVersionCoverageMeasured`):**
      these numbers count services *identified* (a service name, product, or soft
      match). For version-dependent work — advisory matching and P3.3 release
      resolution — what matters is services yielding a **VERSION**, and that is
      **5 of 11** (four in safe mode: vsftpd, openssh, mysql, proftpd; plus Apache
      httpd under intrusive HTTP), not the 6–7 identified. The "6–7 identified"
      figure is right for what it measured but overstates version coverage, and has
      been carried loosely as if it were the matchable count (some references,
      including in review, rounded it toward "8" — the "8th" this very entry already
      rejected). The corrected, version-yielding number is 5/11; the six services
      whose version the corpus cannot extract are backlog B28.
  - **Dashboard shipped this session** (standing requirement): the asset detail
    view renders the attribution, a **"How the OS was concluded"** provenance table
    (which services *contributed*, *agreed*, were *overruled* — the agreed/ignored
    roles exercised when several services carry hints, as the correlate test
    proves), and service rows read "vsftpd 2.3.4 (banner, high)". A claim's
    evidence is reachable on screen, the same rule findings follow.
  - **P3.3 stays blocked (ADR-060):** attribution reaches family-only (and here the
    wrong family), never a release. B24 (Debian-vs-Ubuntu + use the SMTP/MySQL
    Ubuntu signals) and B25 (package→release map) are the two follow-ups.

### Phase 3 — matching

- **S27 — P3.1 version comparators** (ADR-062). `internal/version`: `CompareDpkg`
  (dpkg `verrevcmp` — epoch, `~` ordering, numeric-vs-lexical) and `CompareRPM`
  (rpm `rpmvercmp` — tilde, caret, numeric-outranks-alpha), plus `AffectedRange`
  and the operator forms. **Validated against the distributions' OWN corpora**
  (vendored `rpmvercmp.at` and `Dpkg_Version.t`, with `PROVENANCE.md`) so a pass
  is the comparator agreeing with dpkg/rpm's own test data, not with ours; and a
  **live library oracle differential** (`CVAP_REQUIRE_VERCMP_ORACLE`) against
  `dpkg --compare-versions` and librpm. Go is authoritative over SQL (SQL text
  order disagrees on the tilde). A zero-case parse **fails** (§5.5). **Found (all
  gate-before-push):** an errorlint `As` conversion, a staticcheck `QF1001`, a
  two-`mutate:test` bug that ran every mutation against the last test only (fixed
  to one `-run TestDpkgCorpus|TestRPMCorpus`), and `internal/correlate` +
  `internal/version` silently absent from `DB_TEST_PKGS`.
- **S28 (this session) — P3.2 vendor advisory ingestion, the matching authority**
  (ADR-014, ADR-019, ADR-030, ADR-063). **USN only, deliberately** — RHSA fails
  differently (OVAL/CSAF, per-stream, NEVRA) and building both would compromise the
  first parser's fetch/pack/import boundary; rpm stays proved-in-corpus but not
  proved-in-situ (**B26**, RHSA + a real rpm host as unblocker).
  - **The pipeline** (`knowledge/usn_ingest.py`): `fetch` (online → an advisory
    PACK with provenance: feed, URL, fetched-at, ETag) and `import` (offline,
    idempotent, ADR-019 air-gap path) as **separable** steps. Hostile input is
    **refused, not truncated** — `MAX_FEED_BYTES=64MB`, bounded fields — because a
    partial import is a silent false negative, the exact failure P3.1 was ordered
    first to avoid. Import is injection-safe: CSV + `\copy` into TEMP staging, never
    string-built SQL from feed content.
  - **The write role** (`cvap_knowledge_import`, migration 0034, ADR-063):
    ADR-030's read-only argument stated from the writing side — the role that can
    write detection content is the highest-value identity, so it is scoped to
    exactly the five knowledge tables and, asserted in the migration, never
    BYPASSRLS/SUPERUSER. `TestAppRoleCannotWriteKnowledge` asserts the negative
    (cvap_app refused an advisory INSERT).
  - **★ Acceptance — a real advisory decides a real host, in situ.** USN-1467-1
    (CVE-2012-2122, MySQL auth-bypass), hardy `mysql-dfsg-5.0` fixed
    `5.0.96-0ubuntu3`, ingested from the live USN feed, stored `comparator='dpkg'`.
    `TestAdvisoryMatchInSitu` reads it as cvap_app and — with the comparator the
    ROW names, not one the code assumes — judges Metasploitable's **measured**
    `5.0.51a-3ubuntu5` **vulnerable=true**, while the exact fixed revision and a
    newer one are cleared (the ADR-014 backport case). SQL narrows `(release,
    package)`; Go decides the version relation (ADR-062).
  - **Dashboard shipped this session** (standing requirement): a knowledge-freshness
    panel where **"stale" is a state the API computes**, not a timestamp the operator
    eyeballs — the threshold lives in `knowledge_feed_status.staleness_threshold`
    (in the data), the store's `FeedFreshnessAll` returns `current`/`stale`/`never`,
    and the panel renders the word. Same argument as the exposure count.
  - **Hardy coverage resolved a session-29 concern favorably:** USN covers Ubuntu
    8.04 (537 notices), so Metasploitable — the only real host in scope — can be
    matched end-to-end. A real rpm host is still needed for B26.
- **S29–S30 — P3.3 release resolution, measured before built.** S29: two dev-DB
  queries killed the *suffix* bridge (survives for MySQL only; the bare suffix is
  not release-discriminating) and found the 18-package keyspace too thin to test
  the band — sign-off withheld. S30: widened the hardy import to the full 537 USNs
  (18→190 packages, 22→589 rows) and tested the *band* directly — **it
  discriminates**: hardy's `openssh 4.7p1`/`apache2 2.2.8`/`mysql 5.0.51a` are
  each unique in the keyspace, so the band pins the release with no suffix and no
  rename map. Metasploitable confirmed a valid acceptance host (3 services agree,
  2 swapped builds abstain). The measurement, not an argument, chose the approach.
- **S31 (this session) — P3.3 BUILD: release resolution via upstream band
  (ADR-064).** Option (a)-via-band. Three pieces mirroring B21's split:
  `store.Advisories.ReleasesForProduct` (SQL narrows to a product's packages),
  `domain.ResolveRelease` (pure band voting, threshold, provenance), correlate
  `deriveRelease` (gather votes, promote, under a known family only). The band is
  defined once in Go (`domain.UpstreamBand`) — no SQL band extraction, no
  two-writers drift.
  - **The safety property is the whole argument:** every failure mode is
    UNRESOLVED, never wrong — a collision yields no clean vote, an absent release
    or a swapped build abstains. Unresolved is ADR-061's nullable release =
    family-only. A wrong release would poison every finding; this cannot produce one.
  - **Threshold ≥2 agreeing clean votes, unique leader** (ADR-064): one is a
    single point of failure, two independent services corroborate, ties never
    resolve. Confidence = share of agreeing votes.
  - **The product→package map is content** (`product_packages`, migration 0035,
    `knowledge/product_packages.json`), imported as cvap_knowledge_import — the
    sixth knowledge table, ADR-048's corpus argument, not a Go literal.
  - **★ Acceptance, end to end on the real keyspace:** Metasploitable →
    `family=ubuntu, release=hardy` (3 contributed, 3 abstained, confidence 1.00),
    then the full chain — release `hardy` → P3.2 `FixesFor` → USN-1467-1 fixed
    `5.0.96-0ubuntu3` vs measured `5.0.51a-3ubuntu5` → **vulnerable (CVE-2012-2122)**.
    First time family, release, comparator and advisory data meet on one host.
  - **Dashboard shipped** (standing requirement): the asset page's "How the release
    was concluded" table — which services voted, agreed, and **abstained (with the
    reason: no analogue vs band mismatch)**, because absence-is-not-evidence must be
    visible. A resolved release now carries its evidence the way the family does.
  - **Confidence tiered, not flat (ADR-065):** 2 agreeing → 0.80 (medium), 3 → 0.90,
    ≥4 → 0.95 (high), scaled down by dissent, so a unanimous pair outranks a disputed
    plurality and the finding pipeline can weight a two-vote release below a four-vote one.
  - **★ Coverage measured, and the S26 figure corrected (ADR-065,
    `TestMetasploitableVersionCoverageMeasured`):** running Metasploitable's 11
    banners through the real matcher yields a VERSION for **5 of 11** — four in safe
    mode (vsftpd, openssh, mysql, proftpd) plus Apache httpd 2.2.8 under intrusive
    HTTP probing — of which **2 band-vote hardy in safe mode** (openssh, mysql), 3
    with the intrusive Apache. **S26 correction:** the S26 entry above published
    "6/11 → 7/11", which counted services *identified* (including versionless
    telnet/Postfix/VNC); the number that matters for version-dependent work
    (matching, release resolution) is **5/11**, and it has been carried loosely
    since. This is a **counting difference, not a regression** — the four safe-mode
    matchers are all present and the test locks them. Release resolution reaches
    exactly as far as service identification: the six services whose version data
    the corpus can't extract (Samba, Apache, PostgreSQL, UnrealIRCd, Postfix,
    distccd) are **backlog B28** — a B22 service-ID gap that bounds P3.3's real-host
    reach, NOT a resolver limitation.
- **S32 — checkpoint before P3.4.** No feature code: synced this map (nine sessions
  stale), positioned B29 before P3.4, recorded the two-vote threshold as reasoned-
  not-validated (ADR-066, a review trigger), and confirmed P3.4's ADR-060 entry
  conditions met.
- **S33 (this session) — B29: the keyspace coverage window, before P3.4 (ADR-067).**
  The last matching-integrity item. A release's advisory feed covers only until its
  support ends; a host past that window has exposure the keyspace cannot know about,
  so a no-match read as **clean** — a silent false negative. Now it reports
  **cannot-know**.
  - **Coverage is DATA, not a constant:** `release_coverage` (migration 0036)
    ingests each release's EOL/ESM dates from `ubuntu.com/security/releases.json`
    (`fetch-releases`/`import-releases`, offline per ADR-019). Real dates for current
    releases (jammy ESM 2032, focal 2030); the feed returns a degenerate placeholder
    for pre-ESM releases (hardy = release date 2008), recorded as
    `coverage_source='feed-degenerate'` with the empirical newest-advisory date as
    the honest display value — the decision (`esm_expires < now`) holds regardless.
  - **Matching returns a state** (`domain.ClassifyMatch`): vulnerable / clean /
    **cannot-know** — the fourth application of absence-is-not-evidence (after no
    advisory for a package, no analogue for a product, no corpus instance for a
    rule). A positive match stays vulnerable; only a *no-match* on an out-of-coverage
    release becomes cannot-know. The three states are distinct and stay distinct.
  - **Dashboard shipped** (standing requirement): the knowledge panel renders
    per-release coverage beside feed freshness; the asset page carries a prominent
    caveat when its release is out of coverage — "an empty finding list here means
    cannot-know, not clean."
  - **★ Acceptance, demonstrated not asserted** (`TestReleasePastCoverageWindowIsCannotKnow`):
    hardy (ESM ended, degenerate date, out of coverage) → a no-match is cannot-know;
    jammy (ESM 2032, covered) → a no-match is clean. The two differ; the collapse of
    one into the other was the entire defect.
  - **`release_coverage` is the 7th knowledge table / 16th ERD-undrawn** — recorded
    in ADR-067 and this file's lists, folded into B27.
  - **The three states reach the WIRE, not only the store (ADR-068).** The defect
    collapses again if the finding-list endpoint returns an empty array for both
    clean and cannot-know, so `advisory_status` is a server-owned enum on the asset
    (`no_release`/`clean`/`cannot_know`/`vulnerable`) and on the asset-scoped finding
    list. "Clean" is emitted only for a resolved release in coverage — never the
    emptiness of a list — so a client that ignores the field gets no verdict, not a
    wrong one. `domain.AssetAdvisoryStatus` (pure); rendered as the asset's advisory
    posture in the UI.
  - **B30 recorded (not decided):** the keyspace holds packages that were *advised*,
    not packages that *shipped*, so a covered release with a never-advised package
    reads clean for the wrong reason — B29's defect one layer in. Its two candidate
    fixes are the same two P3.3 weighed: a release-baseline feed (option (b)) or
    Phase-4 credentialed assessment. This is the **second** independent gap pointing
    at that pair — (b) is now a defect fix not an enhancement, and the case for
    pulling Phase 4 forward is stronger. Not a P3.4 blocker.
  - **P3.4 is unblocked:** all matching-integrity floors (P3.1 comparators, P3.2
    advisories, P3.3 resolution, B29 coverage) are in; the finding set P3.4 will
    prioritise is complete-or-honestly-bounded, never silently incomplete.

- **S34 (this session) — P3.4: KEV and EPSS prioritise the finding set (ADR-069).**
  The finding list gains a meaningful sort order for the first time — priority, not
  severity. CVSS scores badness in the abstract; KEV says someone is exploiting it,
  EPSS says how likely that is to start. A KEV CVE on a reachable asset outranks a
  higher-CVSS finding nobody exploits, and **that inversion is the whole point.**
  - **Two feeds ingested on the P3.2/P3.3 pattern** (`knowledge/risk_ingest.py`,
    `make knowledge-kev`/`knowledge-epss`): CISA KEV (~1700 CVEs) and FIRST EPSS
    (~370k, daily). fetch/import separable, offline per ADR-019, provenance and
    freshness in `knowledge_feed_status`. **EPSS staleness threshold is 2 days**
    (tighter than USN's 7 — it updates daily); KEV's is 7.
  - **Bounds that refuse, not truncate** (ADR-069, requirement 2): EPSS is every
    published CVE, so USN's 5000-notice cap would bite. Raised **deliberately with
    the number stated** — `MAX_EPSS_ROWS = 1,000,000` (headroom over ~370k) and a
    `128 MB` decompressed-size cap guarding a gzip bomb; a larger body is refused,
    because a truncated risk feed is the silent under-reporting P3.1 was ordered
    first to prevent.
  - **The model is an ADR before code** (ADR-069): a lexicographic order —
    **KEV > internet-reachable > criticality > EPSS > CVSS > severity** — bit-packed
    into `priority_score` so KEV (weight 1e9) dominates the sum of every lower term.
    The inversion is **structural, not tuned**: no CVSS or EPSS value can lift a
    non-KEV finding above a KEV one.
  - **Exposure is a weak input, and the model says so** (ADR-069): `internet_reachable`
    is zone-derived and largely unwritten (backlog #6), so today the order degrades in
    practice to **KEV > criticality > EPSS/CVSS**. Stated, not papered over — unknown
    exposure is its own value, not ranked as "internal".
  - **Absence is not evidence, the FIFTH application** (ADR-069, requirement 4): a CVE
    absent from KEV is **unlisted**, not known-unexploited (no boost, no penalty); a
    CVE with no EPSS is **unscored**, not probability 0 — the long-tail key is
    `COALESCE(epss, cvss/10)`, so an unscored finding ranks by the CVSS we know, never
    drops to the bottom. Only a finding with **neither** is genuinely no-signal, and it
    is flagged `unscored`. (After: no advisory for a package; no keyspace analogue for
    a product; no corpus instance for a rule; no coverage for a release.)
  - **Dashboard shipped** (standing requirement): the finding list is priority-ordered
    by default with a **KEV badge** + `priority_basis` + EPSS column; the detail view
    carries a Priority section (KEV/EPSS/CVSS with honest null semantics — "unlisted",
    "unscored", "unknown"). The knowledge panel already picks up both feeds' freshness
    via `FeedFreshnessAll` (no API change). List cursor is now `(priority_score, id)`.
  - **`kev`/`epss` are the 8th/9th knowledge tables, 17th/18th ERD-undrawn** — recorded
    in ADR-069 and this file's lists, folded into B27.
  - **The P3.4 ordering acceptance is DEFERRED to S35, deliberately.** The first cut
    demonstrated the inversion on a seeded fixture (`TestFindingSetOrdersByPriorityNot-
    Severity`); on review that was two new things at once — a matcher and an ordering
    claim about the matcher's output, written the same session. The fixture was
    removed and the ordering acceptance re-grounded on **real** advisory findings, next
    session. The finding that CVE-2012-2122 is NOT in KEV (so the KEV inversion needs a
    different pair — CVE-2012-1823 over CVE-2007-2447) still stands and carries forward.

- **S34b (this session) — the advisory→finding PATH, P3.3's last link (ADR-070).**
  Root-caused why every finding's `vuln_def_id` was NULL: not a dropped write, a
  **path that never ran**. `evaluateFindings` produced only rule-engine findings;
  the advisory matcher's decision (`FixesFor` → comparator → `Vulnerable`) lived only
  in a test; `store.Finding`/`Upsert` had no `vuln_def_id` field at all. So the whole
  ADR-067/068 state machine could only ever emit clean/cannot-know — **`vulnerable` was
  unreachable in production**, the B29 coverage work sitting on a state nothing could
  reach.
  - **Built the path** (ADR-070): `evaluateAdvisories` runs in the correlation
    transaction after release resolution — gather (`PackagesForProduct`, `FixesFor`,
    `AdvisoryVulnDefs`) in the store, decide the version relation in Go (ADR-062),
    raise a finding per matched CVE. `store.Finding` gained `VulnDefID`+`Source`;
    `Upsert` writes them.
  - **Four model decisions, each settled in the ADR:** dedup `(asset, package, cve)`
    — the credentialed-row shape, not the port, so one package behind two ports is one
    finding; `source='network'` because source names how the evidence was *obtained* (a
    banner), while the package-shaped dedup + medium confidence say the claim is about a
    package (Phase 4 credentialed supersedes on the shared key); **one** seeded
    `advisory-version-match` rule (new `engine='advisory'`, migration 0038/0039) with
    the CVE in `vuln_def_id` (ADR-009's split), not one rule per advisory; reach bounded
    by B28 (which services carry a version) and B30 (advised ≠ shipped), stated so the
    first findings are not read as complete coverage.
  - **★ Acceptance, real not seeded** (`TestAdvisoryFindingProducedOnMetasploitable`):
    the correlation sweep — nothing in the test does the match — produces a finding
    for **CVE-2012-2122** on `mysql-dfsg-5.0` (installed `5.0.51a-3ubuntu5` < fixed
    `5.0.96-0ubuntu3`, dpkg), source `network`, dedup `advisory|{asset}|mysql-dfsg-5.0|
    CVE-2012-2122`, evidence carrying the advisory, versions and comparator. On the dev
    DB's full USN keyspace the same host raises **62** advisory findings; on a seed-only
    CI DB, one. The session stops here: real advisory findings exist, ready for S35 to
    order.
  - **Follow-up recorded:** advisory findings have no remediation lifecycle yet (the
    rule-finding `closeRemediated` is endpoint-keyed and does not apply to a
    package-keyed finding) — a patched package leaves its finding open until that lands.
    Noted in the backlog, not silently left.

- **S34c (this session) — advisory-finding confidence composed, not constant (ADR-072).**
  The path shipped with a constant confidence (0.5); a constant is as wrong as 1.00
  because it hides which input is weak. An advisory finding rests on four inputs and
  only one — the dpkg/rpm comparator — is exact; the other three are inferences:
  release resolution (ADR-065 tiers), version extraction from a banner (ADR-014
  medium), and the product→package map (content, ADR-064/071).
  - **Confidence is the MINIMUM of the three inferences** (the comparator contributes
    1.0 and never binds). Min, not product: a product of four plausible values
    collapses misleadingly low and cannot be inverted; min says "as trustworthy as the
    weakest input" and a 0.60 finding means every input was ≥0.60 with the weakest
    exactly there. The finding's evidence carries the breakdown, so the weakest input
    is visible, not reconstructed.
  - **Acceptance updated:** the Metasploitable finding is now **0.60** (banner-bound:
    release 0.80, banner 0.60, map 0.90), not the old 0.5 — an inferred claim that
    visibly does not borrow the certainty of the exact comparator beneath it.
  - **Ordering signal recorded in the backlog** (not only in the items): three
    independent gaps — B30 (completeness), B31 + ADR-071 (lifecycle/identity), ADR-072
    (version confidence) — now converge on credentialed assessment. Three distinct
    gaps sharing one fix is structural, and it belongs where the sequencing is decided.
    Phase 4 is **not** pulled forward yet; the accumulation is made visible for when it is.

- **S34d (this session) — the confidence constants were invented; corrected to 1.0
  pass-throughs (ADR-073).** ADR-072's 0.60 banner and 0.90 map were first-value
  guesses dressed as a composition, and `minConf` carried a 0.5-ish floor (skip ≤0,
  unknown-method default 0.50) — the latent-guard shape that does nothing today and
  becomes a wrong answer when a real weak input appears. Corrected: version extraction
  and the product→package map contribute **1.0** (no principled sub-1.0 value yet), so
  `min()` is the **release confidence alone** today; the floor is dropped so a weak
  input passes through honestly (a finding that inherits 0.4 carries 0.4). Stated as a
  **coverage** statement, not a defect: the min mechanism is correct and untested as a
  composition until a genuinely weak input exists. **Review trigger:** B28's
  response-shape version extraction is the first sub-1.0 input that will exercise it.
  The Metasploitable acceptance now asserts **0.80** (release-bound), and the backlog
  ordering-signal bullet is corrected — version is not a cap today, it becomes one at B28.

- **S36 (this session) — P3.4's ordering acceptance, on REAL findings (ADR-069).**
  The KEV/EPSS ingestion, the priority model, the bounds, the grants, and the UI all
  shipped in S34 (ADR-069, `87b2d6e`); this session did NOT rebuild them — it verified
  each requirement against the committed code and landed the acceptance that was
  deliberately deferred until real advisory findings existed (they do, since ADR-070).
  - **Verified against the code, not asserted:** ordering `KEV·1e9 > exposure·1e8 >
    criticality·1e7 > coalesce(epss,cvss/10)·1e3 > severity` (findings.go); absence
    handled by `coalesce(epss, cvss/10)` so an unscored EPSS falls back to the CVSS we
    know, never 0 — the "missing value quietly becomes a zero" trap avoided; bounds
    `MAX_EPSS_ROWS=1,000,000` + 128 MB gunzip guard, refuse-not-truncate; freshness KEV
    7 days / EPSS 2 days; grants SELECT-only `cvap_app`, writes `cvap_knowledge_import`;
    UI KEV badge + priority-sorted list + EPSS column.
  - **The CVE-2012-2122 check, answered from the feed not from memory:** it is NOT in
    KEV (in_kev=f, EPSS 0.965, no CVSS), so it cannot show the inversion. The pair that
    does, both real on Metasploitable and both KEV/EPSS-verified: **CVE-2012-1823**
    (PHP-CGI, in KEV, EPSS 0.99998, CVSS **7.5**) and **CVE-2007-2447** (Samba usermap,
    not KEV, EPSS 0.71, CVSS **10.0**).
  - **★ Acceptance, on pipeline findings not a fixture**
    (`TestFindingSetOrdersByPriorityOnMetasploitable`): the sweep produces advisory
    findings for both CVEs (via ADR-070), and `Findings.List`'s own priority order ranks
    **CVE-2012-1823 at #0** (score 1,001,000,003) **above CVE-2007-2447 at #5** (score
    710,004) — the KEV CVE outranking the higher-CVSS non-KEV one, KEV's 1e9 boundary
    the structural driver. The finding set orders by priority, not severity.
  - **Exposure is the model's weak term, stated (requirement 4):** `internet_reachable`
    is zone-derived and unwritten (#6), so the 1e8 exposure term rarely discriminates and
    the order degrades in practice to KEV > criticality > EPSS/CVSS — the same honesty
    ADR-071/073 applied to confidence, recorded in ADR-069.
  - **Absence is not evidence — recount:** ADR-069 (frozen) called KEV/EPSS the *fifth*
    application; with ADR-070's "no version = no match, not safe" (B28) and "advised ≠
    shipped" (B30) landing between, KEV/EPSS is more precisely the **sixth**. The ADR is
    not edited (freeze); the recount is recorded here.

- **S37 — Phase 3 close-out: internet_reachable resolved, the console designed.**
  - **internet_reachable (backlog #6, open since S18) decided (ADR-074).** The column was
    `NOT NULL DEFAULT false` and never written true, yet P3.4 made it the priority model's
    1e8 exposure term — an *inert* input, not merely weak, disclosed twice (ADR-059/069)
    without a decision. Migration 0040 drops the column and its dead index; the exposure
    term derives from `zone_type IN ('external','dmz')` — the term is now **categorical**
    (a zone classification), not a reachability probability, and the ceiling is stated once.
    The real determination (a vantage-point observation from an external scan point, which
    the architecture supports and no engine performs) is named as **B32**, so the deletion
    is a decision with a path, not an abandonment.
  - **A real p95 regression, caught not masked (ADR-074 follow-up).** The zone_type
    derivation first joined `scan_zones` inside a correlated per-finding EXISTS; the load
    test caught the finding-list p95 climbing (375ms local, over the ceiling on a slow CI
    runner). Fixed by evaluating the external/dmz zone set once as an InitPlan (113ms). The
    lesson is §5.10: an environmental flake and a real regression wore the same mask, and
    confirming instead of re-running surfaced it.
  - **Enterprise console (#12) designed, not built (docs-only).** IA (landing-first,
    triage-centric, reuse the honest detail views) + a visual design language extending the
    shipped tokens, in `docs/superpowers/specs/2026-09-09-enterprise-console-design.md` with
    a visual canvas; the backend-reads map phases the future build (triage on existing reads;
    landing/health/trends need new reads). Rung 1 (accurate-first) is the hard constraint.

- **S38 (this session) — checkpoint: Phase 3 close-out + the Phase 4 sequencing decision.**
  No feature code. This map synced (S32–S37, inventory, phases table, §5 patterns 5.7–5.10);
  the backlog re-ordered against a done Phase 3 (B29–B34 positioned); and the Phase 4
  sequencing decision set out for the operator in `docs/phase-4-sequencing-decision.md` —
  three gaps (B30, B31, B33) converge on credentialed assessment; the recommendation is to
  hold Phase 4 behind a named trigger and take the enterprise console then B28 first, with
  the condition under which that flips stated. The operator decides.

### What Phase 3 changed — a different product (S25–S37)

The way S31 recorded what P3.3 changed, this records what the whole phase changed. Phase 2
closed (S23) with an **unauthenticated exposure scanner**: it found hosts and services, ran
evidence-based rules over them, and reported TLS/config/hygiene findings honestly. It did not
know CVEs.

Phase 3 made it a **CVE-matching vulnerability scanner**. The product now, on a real host,
attributes the OS family and distro release from banners (ADR-061/064), resolves the release
by upstream-version band voting (ADR-064/065), matches installed versions against **vendor
advisories with backport awareness** — the comparator the advisory names, Go-authoritative,
never NVD ranges (ADR-014/062) — states **cannot-know** where the advisory keyspace cannot
reach (ADR-067/068), turns a match into a **CVE-linked finding** (ADR-070) with a confidence
composed from its weakest input (ADR-072/073), and orders the finding set by **exploitation-
weighted priority** — KEV dominates, then exposure, criticality, EPSS, CVSS (ADR-069) — so a
known-exploited CVE outranks a higher-CVSS one nobody has exploited. That inversion, on real
Metasploitable findings, is the phase's proof.

That is a different product from the one S23 closed with. Its ceiling is honest and named:
every match rests on a banner-inferred package identity (medium confidence), which is where
the Phase 4 sequencing decision picks up.

---

## 3. Artifact inventory (as of S38)

**S32–S38 delta (Phase 3.4 + close-out).** New since the S31 snapshot: ADRs 069
(KEV/EPSS prioritisation), 070 (advisory→finding path), 071 (dedup map fragility),
072 (confidence = min of inputs), 073 (confidence 1.0 pass-throughs), 074 (exposure
from zone_type, #6 resolved). Migrations 0037 (`kev`/`epss`), 0038/0039 (advisory
engine kind + rule), 0040 (drop `internet_reachable`). `knowledge/risk_ingest.py`
(`make knowledge-kev`/`-epss`). `internal/correlate/advisories.go` (advisory matcher).
The finding list is priority-ordered with a KEV badge + EPSS column, and the exposure
term is a categorical `zone_type` derivation (ADR-074). Design docs (no feature code):
`docs/superpowers/specs/2026-09-09-enterprise-console-design.md` (+ visual canvas) and
`docs/phase-4-sequencing-decision.md`. Backlog grew by six — B29 (done S33), B30, B31,
B32, B33, B34 — with B30/B31/B33 converging on credentialed assessment (the §4 decision).
Gates unchanged in shape (`make ci` + the `db-gates` load test); the S37 load-test flake
was a slow-runner p95 fragility, not a gate change. The rest of this section is the S31
snapshot and is not re-verified here; the deltas above are the current additions.

**ADRs.** 001–074 accepted (`docs/adr/`, index at `000-index.md`). Corrections are
recorded as new ADRs, never edits: 028 corrects the pre-release contract; 041
supersedes 033; 044 corrects 042; 046 corrects 045; the Phase-3 matching chain is
059→060→061→062→063→064→065→066→067→068→069→070→071→072→073→074, each refining the last, none rewritten. The freeze
rule holds — a committed ADR is superseded, never rewritten.

**Migrations.** 0001–0035. Every tenant-scoped table carries `tenant_id` + RLS
(`USING` and `WITH CHECK`) in its creating migration. `observations` is
range-partitioned from creation; `evidence` is deliberately not (ADR-016). The
Phase-3 additions are all **global knowledge** tables (no `tenant_id`, ADR-030):
0034 (`knowledge_feed_status` + the `cvap_knowledge_import` role, ADR-063) and 0035
(`product_packages` + the asset release columns, ADR-064).

**Phase-3 matching artifacts (S27–S31).** `internal/version` (dpkg/rpm comparators,
corpus- and oracle-validated, ADR-062); `knowledge/usn_ingest.py` +
`import_product_map.py` (offline advisory + product-map ingestion, ADR-019/063);
`internal/domain/release.go` (pure band-vote resolver, ADR-064/065);
`store.Advisories` (`FixesFor`, `ReleasesForProduct`, `FeedFreshnessAll`); the asset
page's release-provenance and knowledge-freshness surfaces.

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

### P3.4 entry conditions (S31 checkpoint) — met, with two bounding caveats

P3.4 (KEV × EPSS × internet-reachable prioritisation, ADR-059) requires P3.3 —
advisory matching — working end to end. It is:

- **ADR-060 B21 (attribution reaches the distro RELEASE and promotes it): MET.**
  `domain.ResolveRelease` (ADR-064) resolves the release and `SetRelease` promotes
  it; the acceptance reaches `Ubuntu 8.04 / hardy` on the real host — the exact
  `Ubuntu 8.04` bar ADR-060 set.
- **ADR-060 B22 (version extraction reaches the package + version): MET for the
  corpus-covered services.** The chain runs on `openssh 4.7p1` and `mysql 5.0.51a`
  in safe mode; `apache2 2.2.8` — ADR-060's named bar — is reached under intrusive
  HTTP probing. The gap (Samba, safe-mode Apache, +4) is measured and named in
  **B28**, and it bounds *reach*, not correctness.
- **The chain closes end to end on a real host** (Metasploitable → CVE-2012-2122),
  which is the substantive entry condition, not a checkbox.

So P3.4 may begin. Two caveats bound the finding set it will prioritise, both named
and neither silent: **B29** (a release past its feed's coverage window is silently
under-reported — positioned **before P3.4**, because prioritising an incomplete set
is triage built on sand), and **B28** (reach is bounded by service identification).
The two-vote resolution threshold is reasoned, not yet validated at its boundary
(**ADR-066**, a review trigger). None of these blocks P3.4's *mechanics*; B29 is the
one the operator chose to place ahead of it.

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

### 5.7 A correct model undone by the query that reads it

The first six patterns are about a *value* being wrong or unread. This one is
different in shape: the model is **right** and the layer that reads it collapses the
answer anyway. The decision is sound; the query that surfaces it is not, and the
output is wrong while every test of the scorer passes.

Two instances, and the second is why this is now its own pattern:

1. **`LIMIT` with no `ORDER BY`** (`internal/store/oidc.go:169`, and the assets CSV
   cap, `assets.go:471`). The row set is correct; a `LIMIT` over it with no order
   returns an *arbitrary* subset, so "the newest N" or "the one match" silently
   becomes "some N" / "some row". The fix was an explicit `ORDER BY` before the
   `LIMIT` — the decision about which rows was moved into the query that reads them.
2. **The P3.4 priority model vs its ordering query.** `priority_score` is a correct
   lexicographic encoding (KEV dominates, ADR-069); but the finding set's order is
   whatever the `List` query's `ORDER BY priority_score DESC, finding_id DESC` and
   its keyset cursor produce. A scorer test — "CVE-2012-1823's score > CVE-2007-2447's"
   — can pass while the *list* is mis-ordered by a wrong `ORDER BY`, a cursor
   comparison with the wrong sign, or a coalesce that lets a null sort high. The
   scorer being right does not make the order right.

**Why it is its own pattern:** the scorer and the reader are different code with
different tests, and the scorer's test is the tempting one to write because the
scorer is where the interesting logic lives. But the *order* is the product — an
operator triages the list, not the `priority_score` column — so a test that asserts
the score and not the order is [[test-that-proves-nothing]] with a plausible alibi.

**How to apply — test the ordering, not the scorer.** The P3.4 acceptance
(`TestFindingSetOrdersByPriorityOnMetasploitable`) asserts on `List`'s *output rank*
(CVE-2012-1823 at a lower index than CVE-2007-2447), not on the `priority_score`
arithmetic — so a mis-ordering `ORDER BY` or a broken cursor fails it, and a correct
scorer with a broken reader cannot pass. For any decision a query surfaces, the test
drives the query and asserts the order/selection it returns, never only the value the
decision computed.

### 5.8 An invented constant dressed as a computed value

ADR-072 composed an advisory finding's confidence as `min(release, version, map)` and
assigned the version and map inputs first-value constants — `0.60` for a banner, `0.90`
for the product→package map. They read as measurements. They were guesses. `min()`
*looked* like it weighed three inputs when two were made-up numbers standing in for
signals that did not exist yet, and a reader would have trusted a 0.60 as if it meant
something. ADR-073 corrected them to **1.0 pass-throughs** — so `min()` is honestly the
release confidence alone today, "correct and untested as a composition until a genuinely
weak input appears (B28)," stated as coverage rather than certainty.

**Why it is its own pattern:** the danger is not a wrong number, it is a *plausible* one.
A fabricated constant with a reasonable value passes every test, satisfies review, and
misleads exactly because nothing flags it — it is [[measure-dont-read]] inverted: a value
presented as measured that was never measured. **How to apply:** a value that stands in
for a signal you do not yet compute is a **1.0 pass-through (or an explicit "unknown"),
not a plausible guess** — make the absence of the signal visible, and record the trigger
(the real input) that will replace it. The same shape, one layer up, is §5.9.

### 5.9 A gap disclosed instead of decided

`internet_reachable` was disclosed as a weakness in ADR-059 and again in ADR-069 — named,
explained, and left. Twenty sessions unwritten. Disclosure felt like diligence, but a gap
disclosed twice and never decided is **a decision nobody made**: ADR-069 even misdescribed
the state ("the read derives from `zone_type`") to make the disclosure read as handled,
when the code still read the dead column. ADR-074 ended it with a decision — drop the
column, derive from `zone_type`, state the ceiling **once** — and named the real mechanism
(B32) so the deletion was a decision, not an abandonment.

**Why it is its own pattern:** an honest disclosure is not free. Each restatement makes the
next reader believe the gap is understood and handled, so it accretes trust it has not
earned, and it can drift from the code (069's misdescription) because nothing tests a
prose hedge. **How to apply:** the second time a gap is about to be disclosed rather than
fixed, that is the signal to decide it — write it or delete it — because a third disclosure
is not more disclosure, it is proof no one will. (This is the process-level twin of §5.6's
field-nobody-reads: 5.6 is data with no consumer, 5.9 is a gap with no decision.)

### 5.10 An environmental flake and a real regression wearing one mask

The S37 load test failed in CI three ways that looked identical from the badge — a 15-minute
timeout, then a coarse-ceiling miss (1264ms), then another. Two of them were a ~10x-slow
GitHub runner (environmental, ADR-058 accepts it); one of them, on a run that completed, was
a **real p95 regression** ADR-074 had introduced (a per-finding `scan_zones` join). The
temptation was to file all three as "the load-test flake" and re-run. Confirming the
completed run's log instead of re-running surfaced the genuine regression, which was then
fixed (InitPlan, 113ms).

**Why it is its own pattern:** a known-flaky gate is where a real regression hides best —
every failure is pre-attributed to the flake, so the real one is waved through on the third
re-run. **How to apply:** before re-running a flaky gate, read the failure. An environmental
flake and a real regression can wear the same mask, and only the log tells them apart — a
re-run that goes green does not prove the earlier red was noise, it just reshuffled the
runner. ([[gate-before-push]] extended: also *read the gate* before dismissing it.)

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
