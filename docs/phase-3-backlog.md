# CVAP — Consolidated backlog & Phase 3 sequencing

Everything deferred, scheduled, or found-but-not-fixed, in one ordered list. It was
scattered across ADRs, session summaries, and agent memory; this is the single
place it is acted from. **The ordering is the deliverable** — the before/during/
after marking against Phase 3 is what makes this a plan rather than a pile.

Phase 3 itself is sequenced in [ADR-059](adr/059-phase-3-sequence.md). Where this
backlog and ADR-059's *consequence* notes differ on an item's timing — #6
(`internet_reachable`) moved from during to **before** Phase 3 after ADR-059 was
accepted and frozen — **this backlog is authoritative for item timing**; ADR-059's
Phase-3 stage sequence (P3.1–P3.6) is unchanged.

**Numbering.** Two ID series coexist here: the doc's `#1`–`#14`, and the operator's
`B`-series used across sessions (`B14` = `#6` internet_reachable, `B15` = `#2` the
four deferred rules). `B21`–`B23` are added below in the B-series. **B21 and B22 are
P3.3's two entry conditions, measured and failed in Session 24 (ADR-060), and are
the next session — before Phase 3 begins.**

## On "owner"

This is a solo build (one operator + Claude Code), so *owner* names the
**subsystem** the work lands in, not a person — it says where the change lives and
which review agents gate it, so two items in the same subsystem are not started in
parallel and each is routed to the right reviewer.

---

## Ordered backlog

### Position as of S31 (checkpoint)

Phase 3 is underway, so the section headers below ("Before / During / After Phase 3") read
against where we now are: **P3.1 (comparators, S27) ✅ · P3.2 (advisory ingestion, S28) ✅ ·
P3.3 (release resolution, S31) ✅ · B29 (coverage window, S33) ✅ · P3.4 (KEV/EPSS
prioritisation, S34) ✅ — the family → release → comparator → advisory → finding chain closes
on real data, and the finding set now orders by priority.**
The ordered front, most-blocking first:

1. **B29 — keyspace coverage window (silent under-reporting): BUILT (S33, ADR-067).** The one
   item positioned ahead of the phase, now done: a release past its window reports cannot-know,
   not clean. P3.4 triages a finding set whose completeness is stated, not silently assumed.
2. **P3.4 — KEV/EPSS prioritisation model + ingestion: BUILT (S34, ADR-069).** The finding list
   orders by priority, not severity: KEV > exposure > criticality > EPSS > CVSS, KEV bit-packed to
   dominate the inversion. `kev`/`epss` feeds ingested (`make knowledge-kev`/`-epss`), bounds raised
   deliberately (`MAX_EPSS_ROWS=1,000,000`, 128 MB gunzip guard). Absence is no-signal, never a low
   value (fifth application). **Ordering acceptance is S35**, deliberately split from the matcher
   (below): the inversion claim is about ordering *real* findings, so it is not built on a matcher
   from the same session. CVE-2012-2122 is NOT in KEV, so the KEV inversion uses CVE-2012-1823 over
   CVE-2007-2447 — carried into S35.
3. **Advisory→finding path — P3.3's last link: BUILT (S34b, ADR-070).** The step that turns the
   S31 verdict into a finding. Root cause of the NULL `vuln_def_id` was a **path that never ran**:
   `evaluateFindings` produced only rule-engine findings, the matcher decision lived in a test, and
   `store.Finding`/`Upsert` had no `vuln_def_id`. Now `evaluateAdvisories` runs in the correlation
   transaction (gather in store, decide in Go, ADR-062), raising a finding per matched CVE — dedup
   `(asset, package, cve)`, `source='network'` (banner-inferred, medium confidence), one seeded
   `advisory-version-match` rule (`engine='advisory'`, migrations 0038/0039) with the CVE in
   `vuln_def_id`. Acceptance: the sweep produces CVE-2012-2122 on Metasploitable's `mysql-dfsg-5.0`
   (62 advisory findings on the full keyspace). This makes ADR-068's `vulnerable` reachable in
   production for the first time. Reach bounded by B28/B30, stated in the ADR.
4. **B31 — advisory-finding remediation lifecycle (NEW, S34b).** Advisory findings (ADR-070) have
   no close-on-remediation path yet: `closeRemediated` keys on re-observed *endpoints* (port/proto),
   and an advisory finding is keyed on the *package*, so a patched package leaves its finding open.
   The fix is the package analogue of the endpoint lifecycle — on a rescan where the package's
   version is now at or above the fix, mark the finding remediated with a transition row. Not a
   blocker for "findings exist" (S34b's scope) but required before the finding set is trustworthy
   over time. Owner: `correlate`. Unblocker: none — a bounded follow-up.
5. **P3.3 follow-ups, alongside or after P3.4:** **B24** (Debian-vs-Ubuntu family correctness)
   and **B28** (service-version matchers — folds into #14's corpus manifest) widen reach; **B25**
   is done (S31). **B27** (redraw the ERD / supersede ADR-029) is a docs task, any time — now at
   eighteen ERD-undrawn tables (`kev`/`epss` added S34).
6. **B26 — rpm proved in situ: ⛔ operator action** (a real RHEL/Rocky/Alma/CentOS host in
   scope), not schedulable as a code session.
7. **Enterprise console (#12): after P3.4**, per ADR-059.

Everything below keeps its original section for provenance; the positions above are current.

### Before Phase 3 — finish the floor before building on it

| # | Item | Owner | Unblocker | Dashboard? |
|---|------|-------|-----------|------------|
| S24 | **Real-network validation (Session 24, before P3.1).** Measure on owned Windows + Linux hosts what real machines say about themselves and whether OS/distro-release attribution survives outside the lab — the entry condition P3.3 depends on (ADR-059). Building advisory matching on lab-only attribution is the wrong order. | `engines` (discovery/fingerprint) | Owned real hosts on a network the operator controls. | n/a (validation) |
| 1 | **ADR-026 local durability across SIGKILL.** The scan point must not lose enqueued results when killed mid-flight. This is the F9 pattern's home — a reliability floor every Phase-3 finding will stand on. | `scanpoint` / `dispatch` | ADR-026 is scheduled (S20); design exists. None. | n/a (reliability) |
| 2 | **The four deferred rules (S15).** Complete the ~20 non-CVE rule set before Phase 3 extends the engine with CVE findings. A complete rule engine is a cleaner base than a half-one. | `rules` / `correlate` | Evaluators exist; rows + corpus entries needed. | Findings screen — exists |
| 3 | **Populate & surface `expected_ack_count`.** The observability that makes the silent-success class visible to an operator: dispatched-vs-acknowledged per scan. Cheap, and Phase-3 scans lean on dispatch health. | `dispatch` → `control/api` → `web` | None. | **Gap — ScanDetail** |
| 4 | **cvap-cli access control.** The CLI runs as the app role and can name any tenant (bootstrap, enroll-token, set-domain). Bound *who* may run it before Phase 3 adds rule-pack import to the CLI's reach. | `cli` / `control` | Needs a short ADR on the CLI trust boundary. | n/a |
| 5 | **Audit-log surface (API + UI).** §2 MVP item, still partial: privileged CLI ops write `audit_events`, nothing reads them. Phase 3 adds more privileged ops (rule-pack import) — wire a read path and a view first. | `control/api` → `web` | None (table exists). | **Gap — no view** |
| 6 | **`internet_reachable` — derive from `zone_type`, drop the column (decided).** The write path never populated the authoritative column; the read path already answers "is this internet-reachable" from `zone_type`. Two answers to one question with the authoritative one empty is worse than one honest derivation — so the column is **deleted** and the `zone_type` derivation is made the single, explicit source. Resolves the two-writers-one-fact (§5.2) before the knowledge pipeline and the P3.4 triage view rest on it. That number is on the operator landing view and is the one most likely to be quoted, which is why it is fixed first, not during. P3.4 consumption (KEV × internet-reachable × EPSS) is unchanged — it reads the one derivation. | `correlate` → `web` (+ migration to drop the column) | None — decided. | **Gap — Exposure / landing view** |
| 13 | **`tls-weak-cipher-negotiated` ships but cannot fire end to end — a coverage claim that lies.** The rule is one of the 13 shipped and fires at the unit level, but the fingerprint TLS client offers only Go's secure cipher suites, so it never negotiates a weak one and a weak-only server cannot be handshaked (measured: handshake fails against nginx offering only ECDHE-RSA-AES128-SHA256). The console would present "weak cipher" coverage the end-to-end path cannot deliver — the rule-coverage twin of #6. Recorded today only in the corpus `uncovered` block; promoted here so it is tracked, not buried. Fix before the enterprise console (#12) claims the coverage. | `engines` | Known: `inspectOnlyTLSConfig` must OFFER the weak suites (as it offers old versions via `MinVersion`) so a server that accepts one is detectable. | n/a (coverage honesty) |
| B21 | **OS attribution reaches a distro RELEASE and promotes it to the asset — P3.3 entry condition #1 (ADR-060, measured & failed).** Session 24: asset `os_family`/`os_version` are `null` on Metasploitable (Ubuntu 8.04); the only signal was a non-authoritative, wrong-distro `Debian` hint with no release; the modern host gave `Ubuntu` family, no release, also unpromoted. Fix attribution to (a) reach the distro **release** from banners and (b) **promote** it to the asset (a non-authoritative hint is dropped at derivation today). **Acceptance:** reach `Ubuntu 8.04` from Metasploitable's SSH/SMTP/MySQL banners and write it to the asset. Scoped to this gap, not general OS work. | `correlate` + `scanpoint` fingerprint | None — measured and scoped (ADR-060). | **Gap — OS empty on every asset** |
| B22 | **Extract product+version from banners the corpus already receives — P3.3 entry condition #2 (ADR-060).** NOT a general work item: specifically pull **product and version** from banner bytes already captured. Apache 2.2.8, Samba 3.0.20, PostgreSQL, VNC and others return `method:none` today though the bytes identify them. **Acceptance set = Metasploitable's eleven services** (apache2 2.2.8, vsftpd 2.3.4, OpenSSH 4.7p1, Postfix, ProFTPD 1.3.1, MySQL 5.0.51a, Samba 3.0.20, …). "If advisory matching cannot get apache2 2.2.8 from an Apache banner that states it, P3.3 has nothing to match." Do **not** tune the corpus reactively to a measured sample — fix the extraction path. | `scanpoint` corpus/banners | None — measured and scoped (ADR-060). | **Gap — service ID** |
| B23 | **Unidentified-service observation surface.** The corpus-maintenance input, DB-only today. Deferred (right call), but the **unblocker is B22, not volume**: fixing version extraction changes what "unidentified" even means, so the surface is reassessed *after* B22 — then decide land-vs-defer. | `web` | **B22.** | **Deferred → reassess after B22** |
| B24 | **Attribution family correctness: `Debian-Nubuntu` → ubuntu, and use the SMTP/MySQL Ubuntu signals.** Measured on Metasploitable (S26): attribution concluded `debian` for an Ubuntu host because the SSH package string `Debian-8ubuntu1` matches the Debian pattern first and the `8ubuntu1` suffix is ignored, as are `(Ubuntu)` in the Postfix banner and `3ubuntu5` in the MySQL version — none set an OS hint. The B21 family-correctness refinement. Not tuned reactively in S26 (measuring-then-tuning-the-sample is what the corpus gate forbids). | `scanpoint` banners / `domain` | None — measured (S26), scoped. | n/a (attribution correctness) |
| B25 | **Release resolution: package version → distro release.** The other half of P3.3's entry condition (ADR-060): map `OpenSSH 4.7p1`/`5.0.51a-3ubuntu5` → `ubuntu804`. Banners carry family, never release, so this is knowledge-pipeline content (P3.1/P3.2 adjacent), not banner extraction. Until it lands, attribution is honestly family-only = unmatched for advisories (ADR-014). **BUILT — session 31 (ADR-064), [p3.3-release-resolution-design.md](p3.3-release-resolution-design.md).** Option (a)-via-band: `domain.ResolveRelease` (pure band voting, threshold ≥2, provenance), `store.Advisories.ReleasesForProduct` (SQL narrows, Go bands), correlate `deriveRelease` (promote under a known family). The product→package map is content (`product_packages`, migration 0035, `knowledge/product_packages.json`). Acceptance passed end to end: Metasploitable → `ubuntu 8.04 / hardy` (3 agreeing votes, 3 recorded abstentions, confidence 1.00), then the full chain — release `hardy` → P3.2 advisory match → **CVE-2012-2122 vulnerable** on the measured MySQL. Safety property: every failure mode is unresolved, never wrong. Dashboard shipped: the asset page's "How the release was concluded" table with abstentions and reasons. **B24** (Debian-vs-Ubuntu family) and a wider per-release import (to resolve more than hardy) remain the follow-ups. | `knowledge` / `correlate` | **Done.** | Asset detail — release provenance (landed S31) |
| B26 | **The rpm comparator is built but not proved in situ — RHSA is the unblocker.** P3.1 shipped `CompareRPM` validated against rpm's own `rpmvercmp.at` corpus and the live librpm oracle (ADR-062), but P3.2 ingested **USN only** (Ubuntu, dpkg): every stored `advisory_fixed_packages.comparator` is `'dpkg'`, so no advisory row exercises the rpm path end-to-end against a real host. USN and RHSA fail differently — RHSA's OVAL/CSAF shape, its per-release stream model, and its NEVRA (epoch/name/version/release/arch) versioning are a different fetch/pack/import boundary than USN's flat JSON — so building both in one session would have compromised the first parser. The rpm comparator is therefore correct-in-isolation but **not proved matchable**. **Acceptance when it lands:** a real RHSA advisory ingested from a real Red Hat feed, stored with `comparator='rpm'`, deciding a real installed NEVRA on a real RHEL/CentOS host — the `TestAdvisoryMatchInSitu` shape, rpm side. Note the session-29 constraint: Metasploitable (the only real host in scope) is Ubuntu, so proving rpm in situ needs a real rpm host in scope first, not only the RHSA parser. | `knowledge` (RHSA fetch/pack/import) + `correlate` | **⛔ OPERATOR ACTION, not a code session.** The blocker is not code — it is a real rpm-based host (RHEL, Rocky, Alma, or CentOS) that the operator must stand up on a network they control and add to `lab/scope.txt` for the session. Until such a host exists in scope, the RHSA parser can be written but its in-situ acceptance (a real RHSA advisory deciding a real installed NEVRA) cannot be run — so this item is stated as needing the operator, because a backlog item whose unblocker is a session that cannot be scheduled is invisible. | n/a (matching authority; no new surface) |
| B27 | **Redraw the v2 ERD and supersede ADR-029 — its own fourteenth-table trigger fired.** ADR-029 enumerates the tables the ERD does not draw and names "a fourteenth arriving unrecorded" as the signal the per-table-annotation approach has stopped scaling. `knowledge_feed_status` (migration 0034, P3.2) is the fourteenth; it is recorded in ADR-063 as a stopgap, but the ADR-029 remedy is to **redraw the ERD in full** with all of them absorbed and mark ADR-029 superseded — and to qualify execution-plan §4.3's "generate migrations from the v2 ERD", which is now wrong by **eighteen** tables (`product_packages`/`release_coverage` added the fifteenth/sixteenth in P3.3, `kev`/`epss` the seventeenth/eighteenth in P3.4). Not a schema change: everything is correct in the schema; this is diagram/record debt that misleads anyone regenerating from the diagram. | `docs` (ERD + ADR-029 supersession) | None — mechanical, but a full-session doc task. | n/a (schema honesty) |
| B28 | **Service-version matchers for the six Metasploitable services that bound P3.3's reach — the specific, measured continuation of B22.** B22 fixed banner extraction generally; this is the named list, measured in S31 (`TestMetasploitableVersionCoverageMeasured`): running Metasploitable's eleven banners through the built-in matcher yields a **version for 5 of 11** — four in safe mode (vsftpd 2.3.4, OpenSSH 4.7p1, MySQL 5.0.51a, ProFTPD 1.3.1) plus Apache httpd 2.2.8 under intrusive HTTP — of which two band-vote a release in safe mode (three with Apache). This corrects the "6–7/11 identified" figure carried since S26, which counted identification regardless of version. Release resolution reaches exactly as far as service identification does, so these are the services whose version data the corpus cannot turn into a `services.version` today, each with its gap type: **(1) SMB/Samba** — the banner carries `Samba 3.0.20-Debian`, no Samba matcher exists at all (highest value: a discriminating package); **(2) HTTP/Apache** — `Apache/2.2.8` is reachable only via the intrusive HTTP probe, no safe-mode path; **(3) PostgreSQL** — version needs a probe, no matcher; **(4) IRC/UnrealIRCd** — soft-matched to the service, banner names the product but no version is lifted; **(5) SMTP/Postfix** — identified but Metasploitable's banner omits the version (needs an EHLO/probe follow-up); **(6) distccd** (and the other S24 method:none services — RPC, NFS, AJP, RMI, X11) — no matcher. This bounds how well release resolution works on ANY real host until the corpus covers more services: it is a service-identification gap, **not** a resolver limitation (the resolver correctly abstains on what it is not given, ADR-064/065). **On surfacing this as a gate:** a service-band-vote gate (fire when few services vote) was considered and rejected — vote count is a proxy that fires alike on corpus regression, host change, and import narrowing, so it produces investigations rather than answers. Its intended home is item #14's corpus manifest (`EXERCISED` / `NOT_PRESENT` / `UNREACHABLE` per service), **one mechanism, not two** — this item feeds that manifest rather than adding a separate gate. | `scanpoint` banners/probes + `protocol` corpus | Capture the exact banners on the next Metasploitable scan (the version-bearing ones for Samba/PostgreSQL/IRC/distccd are recorded from the image, not from this DB, since the S24 scan was cleared); safe-mode vs intrusive matters for Apache/SMB/PostgreSQL (probe-gated). | **Corpus honesty — bounds P3.3 reach** |
| 14 | **Corpus coverage manifest: distinguish "found nothing" from "cannot run here" (§5.5).** The corpus gate reports a true FP/FN over an unstated denominator — a rule set that is ~31% unreachable reports the same numbers as one where everything works. Make the corpus declare, **per rule in the registry**, one of `EXERCISED` (has labelled instances), `NOT_PRESENT` (could fire, lab has no instance), or `UNREACHABLE` (cannot fire — needs a capability that does not exist, blocker named). Assert it as **presence, not property**: every registry rule must have a manifest entry, and a rule added without one **fails the build** (the corpus_check gate, alongside its existing `uncovered`-needs-a-reason check). The pass line reports the split the way corpus-check already reports which halves ran, with FP/FN stated over the exercised set — e.g. `9 rules exercised, 0 not present, 4 unreachable (2 need a TLS version ladder, 1 UDP discovery, 1 a bounded GET probe). FP 0%, FN 0% over the 9 exercised.` The `UNREACHABLE` entries carry the four deferred rules (item #2) with their blockers, so the intended-coverage denominator is stated, not just the shipped one. | `protocol` (corpus gate) + `knowledge` | Folds in #2's four rules and #13; the mechanism is a manifest + a presence check in `.github/scripts/corpus_check.py`. | n/a (coverage honesty) |

### During Phase 3 — folded into the phase's own work

| # | Item | Owner | Unblocker | Dashboard? |
|---|------|-------|-----------|------------|
| B29 | **✅ BUILT (S33, ADR-067) — the keyspace coverage window: a host past its feed's end is silently under-reported.** A release's advisory feed covers only until that release's support ends (EOL, or ESM end). A host running a release **past that window** has real exposure the keyspace cannot know about, so backport-aware matching returns *no advisory match* and the host reads as **clean** — a silent false negative, the exact failure P3.1 was sequenced first to prevent. It has not bitten on Metasploitable because hardy had ESM advisories through 2012, so its feed covers the host's exposure; it **will** bite on the first customer host on a release past its window. The fix is the freshness pattern applied to coverage: record each feed/release's **coverage-end** as data (alongside `knowledge_feed_status`'s freshness threshold, ADR-063), and when a host's release is past it, matching must return a **STATE** — "release out of advisory coverage, findings incomplete" — never silent clean. Same argument as the exposure count and feed freshness: put the boundary in the data so the API answers it and the panel renders it. **Done (S33, ADR-067):** `release_coverage` (migration 0036) ingests each release's EOL/ESM dates from `ubuntu.com/security/releases.json` (`make knowledge-coverage`); `domain.ClassifyMatch` returns vulnerable / clean / **cannot-know**, the fourth absence-is-not-evidence application; the knowledge panel shows per-release coverage beside feed freshness and the asset page carries the out-of-coverage caveat. Acceptance: hardy (ESM ended, degenerate feed date) → cannot-know; jammy (ESM 2032) → clean, demonstrated. | `knowledge` / `correlate` → `web` | **Done.** The advisory→finding consumer (P3.4+) calls `ClassifyMatch`; the state is live on the reads and both surfaces now. | **Landed S33 — knowledge panel coverage + asset out-of-coverage caveat** |
| B30 | **The keyspace holds packages that were ADVISED, not packages that SHIPPED — B29's defect one layer in.** B29 is about a release past its coverage *window*; B30 is per-package *within* a covered release. The advisory keyspace has rows only for packages that had a USN. So on a fully-covered release (jammy, ESM active), a host running a package that never had an advisory matches nothing and reads **clean** — but "clean" here means "this package was never advised", not "this version is unaffected". Same reasoning as B29: absence of a match is not evidence of safety when the keyspace never held the package. `advisory_status = clean` (ADR-068) honestly means "no known advisory vulnerability among advised packages", which is narrower than safe; B30 is about closing that gap, not just labelling it. **Two candidate fixes, and they are the SAME two P3.3's re-decision weighed** (design doc): **(b) a release-baseline feed** — the shipped package set per release, so a package's absence from advisories can be read against what actually shipped; and **Phase 4 credentialed assessment** — reading the package manager gives the *installed* set, so a package's absence from the keyspace stops mattering (you match each installed package and flag the unmatched). Phase 4 fixes it more completely. **Recorded now while the reasoning is fresh (not to be decided this session):** this is the **second independent gap** whose answer is (b) or Phase 4 — B29 was the coverage window, B30 is per-package coverage. (b) was correctly deferred in P3.3 because the band worked; it is now the fix for a *defect*, not an enhancement, which changes its standing. And the case for pulling **Phase 4 forward is stronger than it was**: two independent gaps pointing at the same fix is a different signal from one. **Not a P3.4 blocker** (unlike B29): P3.4 prioritises the findings that exist; B30 bounds completeness within covered releases and needs a larger decision. | `knowledge` (baseline feed) **or** Phase 4 (credentialed) | **Decision deferred — a genuine (b)-vs-Phase-4 choice, now with two instances behind it.** Not blocking P3.4. | n/a (matching completeness; `advisory_status=clean` already states the honest boundary) |
| 7 | **enroll-token API home + UI.** The `/v1/enrollment-tokens` route exists; issuing a token is still a CLI step in the installer. Phase 3 growth (more scan points, rule-pack ops) makes enrollment a console task. Give it a UI home. | `control/api` / `web` | Depends on #5's admin-console surface. | **Gap — no UI** |
| 8 | **Kill-switch UI + safety-mode indicator.** `/v1/kill` and `/v1/scans/{id}/safety-mode` exist as API; the console cannot show or trigger either. Do alongside the admin surface from #5/#7. | `web` | Depends on #5's admin-console surface. | **Gap — no UI** |
| 12 | **Enterprise-console rebuild (dedicated session, after P3.4).** The current UI reads as a developer's view of the data model, not a security console. A dedicated session, not incremental patching. Scope and ordering below. Placed after P3.4 per ADR-059 — the data must carry real confidence and priority distinctions first, or the triage view is designed twice. | `web` | P3.4 complete (CVE-matched findings with KEV/EPSS priority + the full weak-data confidence spectrum). | **Rebuild of all** |

### After Phase 3 — real, but not on the critical path

| # | Item | Owner | Unblocker | Dashboard? |
|---|------|-------|-----------|------------|
| 9 | **Exposure paging.** A scale concern that only bites at large `finding_exposure` counts. | `control/api` / `web` | Measured row counts (ADR-016-style review trigger), not an estimate. | Exposure — exists |
| 10 | **F4–F5 composition test.** The §6.4 matrix covers F4 and F5 individually; composing them is additional distributed-fault coverage. | `protocol` / `dispatch` | None. | n/a |
| 11 | **Sustained-rejection behaviour.** What a scan point does under *sustained* RETRY_LATER / rejection — the backpressure policy, not the single-event handling F20 already covers. | `scanpoint` / `dispatch` | Needs a backpressure-policy ADR first. | n/a |

### Closed this session (S23)

| Item | Commit |
|------|--------|
| `cvap-cli tenant set-domain`, audited | `945bf33` |
| 30-day configurable dev CA (`--valid-for`, 90-day cap) | `86a21e6` |
| Refuse a scan no scan point can run (silent-success) | `6f1d471` |
| Bootstrap requires `--domain` and verifies its own login | `945bf33`, `9d09d5b` |

---

## Standing requirement — dashboard-surface reporting

**From S23 onward, every session that lands a feature answers, in its close-out:**

> Does this feature need a dashboard surface? If so, does that surface
> **exist**, is it **deferred** (with a backlog item), or is it **not needed**?

Copy this checklist into each feature session's summary:

- [ ] Feature: `<name>`
- [ ] Needs a dashboard surface? `yes / no`
- [ ] If yes: `landed this session (screen) / deferred (backlog #N, with unblocker) / not needed (why)`

**The surface lands in the same session as the feature, not in a batch at the end
of a phase.** "Needs a surface" and "deferred to later" are not both acceptable
answers: a feature that produces operator-relevant state ships its surface in the
same session, and deferral is allowed *only* where the surface genuinely cannot
land then — in which case it goes in this backlog as a **named item with an
unblocker**, never as an intention. `internet_reachable` and `expected_ack_count`
are what "later" produces: built, correct, and invisible for twenty sessions. A
feature that produces operator-relevant state and has no way to see it is a
finding, not a nicety — the silent-success scan (S23) was invisible precisely
because dispatch state had no surface.

The dashboard as a whole is kept **continuously current** by this rule. It is not
brought up to date at phase boundaries; it never falls behind in the first place.
(The one-time exception is the enterprise-console rebuild, #12 above, which is a
dedicated session, not incremental patching.)

### Retrospective sweep — built but not surfaced

Applying the requirement backwards. Each is something already built whose state an
operator should be able to see and currently cannot (or only weakly). All are
folded into the ordered backlog above.

| Concept | Built? | Surface today | Verdict |
|---------|--------|---------------|---------|
| `expected_ack_count` (dispatched vs acked) | column exists, unpopulated | none | **deferred → #3** |
| `internet_reachable` (exposure) | column empty; read path derives from `zone_type` | Exposure shows the caveat, not the signal | **before Phase 3 → #6 (decided: drop the column, derive from `zone_type`)** |
| Audit events | written for CLI privileged ops | no API, no view | **deferred → #5** |
| Kill switch (`/v1/kill`) | API exists | no UI | **deferred → #8** |
| Scan safety mode (`/v1/scans/{id}/safety-mode`) | API exists | not shown in ScanDetail | **deferred → #8** |
| Enrollment tokens (`/v1/enrollment-tokens`) | API exists | CLI-driven, no UI | **deferred → #7** |
| Scan-point health | synthesized on `GET /v1/scan-points` (S22) | Scans/scan-point view | **exists** |
| Findings confidence / softmatch / weak-data caveats | S23 SOC pass | Findings + detail | **exists** |
| Knowledge feed freshness (advisory ingestion, P3.2) | S28: state computed server-side from the threshold in the data | Knowledge/freshness panel | **exists (landed S28 with the feature)** |

The two the standing requirement named up front (`internet_reachable`,
`expected_ack_count`) are in this table; the sweep additionally surfaced the audit
log, the kill switch, the safety-mode indicator, and the enrollment-token UI as
built-but-unsurfaced.

---

## #12 in detail — the enterprise-console session

The current dashboard is too simple for what this is: it reads as a developer's
view of the data model — one screen per table — rather than an enterprise security
console. That is a real gap, and it gets its own session, not incremental patching.
Placed **after P3.4** (see ADR-059): designing the triage view before the data
carries real confidence and priority distinctions means designing it twice.

"Enterprise grade" here is concrete, and **the ordering is the point** — each rung
is built on the one above it, and the top rung outranks all the rest:

1. **Accurate first — this outranks everything below it.** Every number on screen
   must be reproducible from the data and must not overclaim. The exposure count is
   zone-derived with `internet_reachable` unwritten; the OS label is
   banner-inferred; softmatch findings have no version. A beautiful dashboard that
   presents weak data confidently is *worse* than a plain one that does not. The
   S23 honest-weak-data presentation (exposure caveat, low-confidence OS label,
   softmatch "unknown") is the floor, not the ceiling — nothing prettier is allowed
   to erode it. This is also why the console comes after P3.4: the confidence
   distinctions must be real before they can be shown honestly.

2. **An operator landing view** that answers the questions an analyst opens the
   tool to ask — *what changed since I last looked, what is worst right now, what
   is not working* — not a list of tables.

3. **Findings triage as the centre of gravity**, not asset inventory. Severity and
   confidence together, filterable, evidence one click away. The product's whole
   argument is that an advisory-matched claim and a banner-inferred one are
   *different claims*; the triage view is where that lands or does not. Build the
   confidence axis as an **open spectrum** so the P3.5 NVD-CPE low-confidence tier
   slots into the existing low-confidence lane without a redesign.

4. **Fleet and scan health visible without hunting:** scan points offline, scans
   blocked for want of capacity (the silent-success class, backlog #3), kill-switch
   state (#8), ingest backlog.

5. **Trend over time.** A finding count with no history tells an operator nothing
   about whether they are winning.

The retrospective-sweep surfaces (#3, #5, #6, #7, #8) are consumed by this rebuild
rather than patched onto the old screens — they are the fleet-health and
honest-count material rungs 1 and 4 need.
