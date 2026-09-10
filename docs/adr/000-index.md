# Architecture Decision Records

Decisions are recorded so a change can be checked against them, and so a future reader
knows what was rejected. Accepted ADRs are superseded, never edited — the
`protect-contracts` hook enforces this.

Create one with `/new-adr <title>`. Check a change against them with the
`adr-compliance` subagent.

| # | Decision | Status |
|---|---|---|
| 001 | Go for core, scan points and agents; Python for knowledge pipelines | Accepted |
| 002 | PostgreSQL as system of record; RLS enforces tenancy | Accepted |
| 003 | Job dispatch via Postgres SKIP LOCKED; broker deferred | Accepted |
| 004 | Broker never exposed; dispatch service fronts it | Accepted |
| 005 | Scan point transport posture: outbound-only, scan-point-initiated mTLS | Accepted |
| 006 | Observation-first — scan points never write assets or findings | Accepted |
| 007 | Asset identity by ranked keys with retained merge evidence | Accepted |
| 008 | Zone is a property of observations; exposure is derived | Accepted |
| 009 | Rule / VulnerabilityDef / VendorAdvisory are separate entities | Accepted |
| 010 | Finding dedup keys are source-specific; SAST keys on symbol not line | Accepted |
| 011 | Scan / Job / Task three-level decomposition | Accepted |
| 012 | Job leases carry monotonic fencing epochs; reassign_safe gates retry | Accepted |
| 013 | Detection split — request-coupled at scan point, evidence-based at core | Accepted |
| 014 | Vendor advisories are authority for packages; CPE is flagged fallback | Accepted |
| 015 | Large evidence to object store; summary in Postgres | Accepted |
| 016 | Observations partitioned monthly, 90-day default retention | Accepted |
| 017 | Tenant-aware always, single-tenant by configuration | Accepted |
| 018 | PKI trust anchor is configuration, not assumption | Accepted |
| 019 | Knowledge data is signed; offline import supported | Accepted |
| 020 | Credentials just-in-time, scoped, memory-only on scan points | Accepted |
| 021 | Safe mode default; detection without impact | Accepted |
| 022 | Protocol versioning is additive-only within a major version | Accepted |
| 023 | Compose first; Kubernetes deferred | Accepted |
| 024 | Scan blast-radius controls | Accepted |
| 025 | Build-versus-consume boundary | Accepted |
| 026 | Result submission contract | Accepted |
| 027 | Engines are separate processes behind a job contract | Accepted |
| 028 | One pre-release correction to the frozen wire contract | Accepted |
| 029 | Schema tables the v2 ERD does not draw | Accepted |
| 030 | Knowledge tables are read-only to the application role | Accepted |
| 031 | Enrolment tenant lookup is a one-value SECURITY DEFINER function | Accepted |
| 032 | The store package exposes no path to a raw connection | Accepted |
| 033 | Pre-tenant resolution is a closed class | Superseded by ADR-041 |
| 034 | No interceptor, middleware or tracing layer may render message bodies | Accepted |
| 035 | A hand-written type holding a secret stores it in a func() string | Superseded by ADR-038 |
| 036 | The sweep enumerates tenants, and that is the only unscoped read | Accepted |
| 037 | Empty means deny for permission lists, unrestricted for constraint lists | Accepted |
| 038 | A secret field is a func of a type that can be zeroised | Accepted |
| 039 | Translated address forms expand exclusions and do not expand allows | Accepted |
| 040 | A target that names an address must parse as one, or the job is refused | Accepted; consequences amended by ADR-044 |
| 041 | Pre-tenant resolution is a closed class of three (supersedes 033) | Accepted |
| 042 | Targets are canonicalised once at planning, and re-canonicalised at the scan point | Superseded by ADR-044 |
| 043 | The route registry is the API contract, and the OpenAPI document is emitted from it | Accepted |
| 044 | Target canonicalisation, restated with three claims corrected (supersedes 042) | Accepted |
| 045 | OIDC identity is the subject, the client is public, and the issuer is a network the deployment trusts | Superseded by ADR-046 |
| 046 | OIDC, restated with the SSRF guard made true and two claims corrected (supersedes 045) | Accepted |
| 047 | The discovery engine may open sockets, and connect scanning is what it may do with them | Accepted |
| 048 | The fingerprint corpus is signed content under a static policy it cannot widen | Accepted |
| 049 | Probes have kinds, and a key exchange is not a payload (supersedes 048 §1 rule 2) | Accepted |
| 050 | The rule engine is closed evaluators and open rules | Accepted |
| 051 | A scope narrowing reaches an in-flight job at its next lease renewal | Accepted |
| 052 | A CSV export refuses over its cap rather than truncating, and export is its own permission | Accepted |
| 053 | The operator SPA is a public static route in the one registry, and its client is a third registry | Accepted |
| 054 | What may live in the repo, now that it is private (hygiene relaxes, good practice does not) | Accepted |
| 055 | The enrollment-token prefix, and its now-half-moot secret-scanning rationale | Accepted |
| 056 | A fault worth testing is one the deployed binary can experience (the §6.4 fault matrix) | Accepted |
| 057 | Credential zeroisation is immediate and independent of submission (derive-before-zeroise) | Accepted |
| 058 | The load test enforces a coarse ceiling in CI and the precise SLO locally (no exposure overshoot) | Accepted |
| 059 | Phase 3 sequences comparators → advisories → KEV/EPSS → NVD, behind a real-network validation; OS attribution gates matching | Accepted (§P3.3 superseded by ADR-060) |
| 060 | P3.3's OS-attribution entry condition, measured against a real host and failed; P3.3 blocked on B21+B22 (supersedes ADR-059 §P3.3) | Accepted |
| 061 | Unauthenticated OS attribution — family, nullable release, confidence, provenance; a reviewable service precedence (B21) | Accepted |
| 062 | Version comparators validated against the distributions' own corpora + a live library oracle differential; Go authoritative over SQL (P3.1) | Accepted |
| 063 | The knowledge-import role writes exactly the five knowledge tables, never BYPASSRLS/SUPERUSER — ADR-030's argument from the writing role's side (P3.2) | Accepted |
| 064 | Release resolution by upstream version band over the advisory keyspace — every failure mode is unresolved not wrong; ≥2 agreeing votes, feed codename, product→package map is content (P3.3) | Accepted |
| 065 | Release-resolution confidence tiered by vote count (2/3/4+), and the measured service-coverage bound — the reach is B22 service identification, not the resolver (refines ADR-064) | Accepted |
| 066 | The two-vote release threshold is reasoned, not validated — review trigger: the first real host resolving on exactly two agreeing votes (refines ADR-064/065) | Accepted |
| 067 | The advisory coverage window is data (release_coverage, ingested EOL/ESM), and a release past it is cannot-know not clean — fourth application of absence-is-not-evidence (B29) | Accepted |
| 068 | The advisory assessment state is a server-owned enum on the asset (no_release/clean/cannot_know/vulnerable) — clean is never an empty finding list, so a client cannot collapse cannot-know into clean (extends ADR-067) | Accepted |
| 069 | KEV/EPSS prioritisation — lexicographic KEV > exposure > criticality > EPSS > CVSS, KEV dominates the inversion; absence (unlisted/unscored) is no-signal, never a low value (fifth application); P3.4 | Accepted |
| 070 | Advisory findings — the matcher's verdict becomes a finding (dedup on package+cve not port, source=network banner-inferred/medium, one advisory-version-match rule with CVE in vuln_def_id, reach bounded by B28/B30); the missing last link of P3.3 | Accepted |
| 071 | The advisory-finding dedup key derives its package from the product→package map (content), so a map change re-keys and reopens existing findings — recorded with its mitigation (store the package on the service) and review trigger; refines ADR-070 | Accepted |
| 072 | An advisory finding's confidence is the minimum of its inference inputs (release resolution, banner version extraction, product→package map) — not a constant, not their product; the exact comparator contributes 1.0 and never binds, and the finding records which input was weakest; refines ADR-070 | Accepted |
| 073 | ADR-072's version-extraction and package-map constants were invented; corrected to 1.0 pass-throughs — min() is the release confidence alone today, correct but untested as a composition, and the 0.5 floor is dropped so a weak input passes through honestly; review trigger is B28's response-shape extraction; refines ADR-072 | Accepted |
| 074 | The exposure term derives from zone_type (external/dmz = internet-reachable) and the never-written finding_exposure.internet_reachable column is dropped — resolving backlog #6, disclosed-not-decided in ADR-059 and ADR-069, with one decision; the ceiling (zone classification, not per-asset reachability) is stated once; auth_required is the sibling left standing for Phase 4 | Accepted |
| 075 | A narrow credentialed slice (Linux/SSH, package inventory only, one VM) as a validation instrument, not full Phase 4 — the operator overruled the S38 memo's console/B28-first ordering because the banner-inference ceiling is a validation limit (the §6.2 accuracy gates cannot be computed on a real host without ground truth); it generates that ground truth, proves rpm in situ (closes B26), and removes B30 for credentialed hosts; the memo's reach reasoning is preserved | Accepted |
| 076 | The credentialed slice holds its credential in the runtime, not the engine (requirement-1's "engine holds the credential" was caught as contradicting frozen ADR-027 and not followed); SSH needs credential+network together, which ADR-027/047 pull apart, so the production engine's placement is deferred and this slice is an operator-run measurement instrument; the FP/FN measurement is the deliverable (the "emits `package` observations" consequence is superseded by ADR-077) | Accepted |
| 077 | The validation instrument does NOT emit observations — rejected on principle (an instrument that measures whether the pipeline is right must not mutate what it measures; a synthetic-task/submission write makes data enter by a path no scan point has and holes the ingest contract for a non-scan-point), so observation emission moves to the deferred production engine; the release-precedence rule (exact `/etc/os-release` outranks the band vote) is built now but dormant, like `vulnerable` in ADR-068 — unreachable until the engine emits, tested in isolation; refines ADR-076 | Accepted |
| 078 | Unauthenticated advisory matching cannot observe the Debian revision — a structural precision limit: the banner gives bare upstream (`10.2p1`), advisory fixes carry epoch+revision (`1:10.2p1-2ubuntu3.6`), so a package whose installed version sits between two advisory revisions is flagged for every advisory including the patched ones. Measured on a real host: 65% FP (13/20), all OpenSSH (the `3.2`+`3.4` USNs already fixed in the installed `3.5`); Exim clean only because its GA sits below every fix (no boundary). Thirty times the §6.2 2% gate, worse on a patched host, unfixable by parsing (the revision is not on the wire) — ADR-014's backport problem from the unauthenticated side; the resolution is credentialed assessment | Accepted |
| 079 | A safe-mode scan reports on services that volunteer a banner, not services that exist — SSH/SMTP send unsolicited banners and are identified passively, HTTP needs a probe safe mode withholds (ADR-048/049), so Apache on an open :80 went unidentified. One of three exposed services invisible: recall is 100% against the identified surface but 23% (TP 7 / FN 24) against the actual one. A correct safety decision (ADR-021) with a measured coverage cost; a safe-mode result is a lower bound on exposure, not a census, and must say so — absence-is-not-evidence applied to identification | Accepted |
| 080 | A single vote that uniquely narrows to exactly one release resolves, at reduced confidence 0.60 (below the two-vote 0.80); two-or-more agreeing keeps the current tiers; a single AMBIGUOUS vote still abstains — supersedes ADR-066, whose review trigger this fired. Silence reads as clean and a unique vote is not the weak/backport case the threshold guarded. Recorded plainly as a SMALLER win than claimed: on the measured host it converts 0 findings into 16 (3 true, 13 false at ADR-078's revision blindness), precision ~19% — silence becomes noise, better only because a wrong finding is disputable and silence is not | Accepted |
| 081 | Credentialed assessment moves NEXT, ahead of B28 and the console — reverses the Phase 4 sequencing memo's deferral (operator overruled it to a slice in ADR-075, then deferred credentialed on the disclosed-ceiling argument, now reversed because measurement killed that argument: 65% FP is being confidently wrong about whether a patched host is patched, unfixable unauthenticated, worse on maintained hosts, and B28 scales it). The memo's reach reasoning stands — unauthenticated stays the discovery/inventory wedge; what changed is that unauthenticated advisory MATCHING cannot carry a product claim, so credentialed is correctness not depth. Next session builds the production credentialed-host path (ADR-076/077/078) | Accepted |
| 082 | Unauthenticated advisory-matching precision worsens MONOTONICALLY as a host is better maintained — the decisive case extending ADR-078. Same OpenSSH, same release, same scanner: `.138` one revision behind = 65% FP, `.146` at the fix (fully patched, not vulnerable) = 100% FP (16 of 16 findings false, including the advisory it is patched to). A bare upstream compares below every revisioned fix, so a fully-patched package fires every advisory; the diligent patcher gets the most-wrong report. Not fixable by reach/corpus/parsing (the revision is not on the wire); the decisive evidence for ADR-081 that credentialed is correctness, not depth | Accepted |
| 083 | Banner capture is non-deterministic and silently moves release resolution between vote tiers — chased, not noted: the same Exim voted on `.138` and not on `.146`, moving resolution from two votes (0.80) to one (0.60, ADR-080). Direct connection shows both Exims greet promptly with near-identical 220 banners, so it is NOT a version/banner difference, NOT a corpus miss, NOT a greeting delay — the scan point failed to capture a banner the host reliably sends. A re-scan of an unchanged host can thus flip resolving/not and confidence tier; the two-vote threshold's corroboration premise needs reliable capture. Scan-point reliability defect, backlog; compounds ADR-079 | Accepted |
| 084 | Phase 4 leads with credentialed assessment — ahead of B28, the console, and any further unauthenticated widening; supersedes the phase-4-sequencing memo and completes ADR-081's reversal against the full measurement set. Records the full arc (memo recommendation → operator overrule to a slice, ADR-075 → deferral on the disclosed-ceiling argument → this reversal) and the process point: the argument was overturned by a host, not by whoever argued better. Evidence by weight: ADR-082 (output wrong, worse the better-maintained the host), ADR-078 (not fixable this side of the wire), ADR-083 (unreliable independently), ADR-079 (safe mode compounds). Reach argument preserved — unauthenticated stays the discovery/inventory wedge; what died is that unauthenticated MATCHING is merely bounded. Order: fix ADR-083, then scope credentialed (settle ADR-027 vs ADR-047) | Accepted |
| 085 | The ADR-082 measurements re-verified under the fixed scan point (ADR-083) — all sequence figures were taken with the broken banner cap live. `.146` corrected: 1 vote/0.60 → 2 votes/0.80, 16 → 20 findings (Exim now appears), still 100% FP — changed in count/confidence, not conclusion. `.138`: 65% unchanged (was lucky, now reliable). Figures stated precisely: 65%/100% are exposed-block (OpenSSH+Exim); OpenSSH-alone is 81%/100%, and the 81%→100% direction holds sharper. Caveat: `.146`'s one-behind Exim USN maps 0 CVEs (keyspace completeness), so "behind" ≠ a truth finding here. ADR-084's decision stands — revision blindness is independent of banner capture | Accepted |
