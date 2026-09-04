# ADR-050: The rule engine is closed evaluators and open rules

**Status:** Accepted
**Date:** 2026-09-06

## Context

Week 6 is the rule engine and the first ~20 non-CVE findings. ADR-025 says build the rule
engine and the rule language ourselves rather than wrapping a scanner, and this is the first
rule engine, so it sets the shape the rest inherit.

The schema had already committed to rules-as-data: `rules.detection_logic` is `jsonb`
(migration 0010). What that jsonb *means* was undecided, and it is the whole decision.

Every rule this session is evidence-based (ADR-013): each reads a certificate, a host key, a
banner or a header that session 13's fingerprint engine already gathered and stored. None is
request-coupled, so all run at Core.

## Decision

### 1. Evaluators are code and closed; rules are content and open

`detection_logic` is `{"evaluator": "<name>", "params": {...}}`. The evaluator name selects a
function from a closed vocabulary in `internal/rules` (twelve of them). The params are the
evaluator's inputs — a threshold, a port list, a header list.

The split follows the fingerprint pack's exactly (ADR-048, ADR-049): the code is amendment-
gated and ships in the build, the content is pack-shippable and signable (ADR-019). A rule
pack can tune a threshold, re-weight a severity, or add a *row* against an existing evaluator
without a deploy — the telnet rule and the FTP rule are two rows against one
`plaintext.service` evaluator, and the second plaintext protocol cost a row, not code. A new
evaluator is a Core deploy, which ADR-013 already says a rule correction is.

**A rule naming an evaluator this build does not implement is refused at load, not skipped**
(`rules.Load`). A rule that silently never fires is the failure a rule engine exists to
prevent: the row is present, the pack says active, and no finding ever raises. Same direction
the fingerprint pack takes with an unknown probe kind.

### 2. A predicate language is deferred, with a concrete trigger

Twenty rules that are mostly "a field compared to a threshold" do not justify designing a
predicate language in a session, and ADR-025's "build the rule language" is honoured by
building the engine that will host one.

**The trigger to write it is concrete: the first rule that needs logic no evaluator provides
AND where adding an evaluator would be the third of essentially the same shape.** Two similar
evaluators is coincidence; three is a language asking to be written. The three certificate-
threshold evaluators (`tls.expired`, `tls.expiring`, `tls.weak_key`) are the ones to watch — a
fourth is where this gets revisited.

### 3. Evaluators are pure; the pipeline does the I/O

`rules.Evaluate` takes a subject and `now` and returns findings, touching nothing. `now` is a
parameter because a rule replayed next year over this year's observations must reach the answer
it reached at the time — which is what makes a rule correction *retroactive* (ADR-013) rather
than only prospective. The zone-type lookup the exposure rule needs is a closure injected by
the pipeline, not a query the evaluator makes, for the same reason.

The subject is built from **observations, not the derived `services` row**: the observation
carries the vantage zone (which exposure is, ADR-008) and the raw evidence excerpt, and
building from observations makes re-evaluation over history the same code path as first
evaluation.

### 4. Findings are keyed and grouped exactly as ADR-010 says

Dedup key is `network | asset | port | protocol | rule` — the asset, not the address, so a host
that moves keeps its findings (session 14's identity work is what makes that possible). The
same issue on one endpoint seen from several vantage points is **one finding with several
`finding_exposure` rows**, never one per zone — the count an executive reads first must not
inflate by vantage-point count. Evaluation runs right after correlation, in the same
transaction that wrote the asset: a finding against an asset whose resolution rolled back would
reference a row that never committed.

### 5. Lifecycle distinguishes "fixed" from "not looked at"

An open finding on an endpoint that was **re-observed** this pass and did not fire is moved to
`remediated`. An endpoint **absent** from the scan is left alone — closing it would report a
fix nobody made. A finding in a remediation state that fires again reopens; a finding an
operator marked `false_positive` or `accepted_risk` does not, because that is a judgement that
the true fact does not matter, and re-detecting it should not undo it every scan.

### 6. The built-in pack is seeded by a migration

`rules` is `SELECT`-only to the application role (migration 0010): knowledge data is signed and
imported out-of-band (ADR-019), never written by the application. The built-in pack is content
that ships with the build, so the writer that ships with the build — the migration set —
seeds it (migration 0032). This is BuiltinCorpus's split for fingerprints: the in-build half is
trusted by provenance, the imported half by an ed25519 signature. The pack's `signature` column
carries `builtin:trusted-by-provenance` rather than a faked signature, so nothing later reads it
as a verified external one. Signed import writes these same rows through a verified path, and
its unblocker is the signing-key custody named in ADR-048. **That importer must reject a
`builtin:` sentinel rather than trying to verify it as a signature** — a schema audit flagged it
as the one landmine here, since nothing reads `signature` as verifiable today and the importer
is where that assumption first bites.

## The rules from §2 that do not ship, by name and unblocker

Week 8 will make a coverage claim, and these are the rules from `execution-plan.md` §2 that
this session does NOT ship. Naming them so none is silently inside the claim.

The `~20 − 13` gap is not four rules subtracted cleanly: two shipped rules (`tls-weak-key`,
`ssh-weak-algorithms`) are not among §2's enumerated examples, so the count is loose in both
directions. What matters is the omissions, listed here — plus one that is out of this session
by design rather than deferred:

- **Default credentials against a short curated list.** §2 names it; it is NOT here and is not
  in the four below. It is request-coupled — a login attempt is an interaction, not stored
  evidence — so under ADR-013 it is a SCAN-POINT rule, not a Core evaluator, and §2's own
  "buffer" line marks default-credential rules as the first thing cut if a week slips. It
  belongs to the scan-point rule path, which does not exist yet. Out of scope, not deferred
  within scope.

The four evidence-based rules that ARE in scope and still do not ship:

- **TLS 1.0/1.1 enabled** and **weak cipher enabled.** What ships is
  `tls.legacy_negotiated` and `tls.weak_cipher_negotiated`, which fire on the version and suite
  the server *negotiated* against a modern client — a direct observation, and high confidence.
  What does not ship is "enabled": a server that negotiated TLS 1.3 may still accept TLS 1.0,
  and this engine cannot see that. **Unblocker: a version-ladder probe** — one handshake per
  version — which is a packet cost per port and a session 13 gap. Until then the two shipped
  rules are narrower than their names in the plan, deliberately.
- **SNMP v1/v2c default community.** Not shipped at all: SNMP is UDP, and discovery finds TCP
  ports only. **Unblocker: UDP discovery** (the same one ADR-049 names for the `mac` identity
  key), plus an SNMP probe kind.
- **Directory listing enabled.** Not shipped: it needs a response body to inspect, and the HTTP
  probe is HEAD by design so a probe cannot pull a body back through the scan point.
  **Unblocker: a bounded GET probe kind.**

## Two shipped rules read the evidence excerpt, not a structured field

`http.no_https_redirect` and `http.missing_headers` parse the status line and headers out of the
sanitised response excerpt, because there is no structured `http` object on the service payload
yet. This is a **latent limitation** in the sense the project's memory records: true and harmless
today, and the thing that breaks the moment the excerpt format changes for an unrelated reason.
Their confidence is 0.75 rather than high because they infer structure from prose. **The fix is
a structured `http` object on the service payload** — status code and headers as a map — gathered
by the fingerprint engine where it already gathers the `tls` object. Named here so week 8 does
not count these as free of that dependency.

## "Untrusted zone" is `external` and `dmz`, and the omission is deliberate

The management-interface rule treats `external` and `dmz` as untrusted and leaves `branch` and
`cloud` out. A branch office is inside the perimeter for some estates and a hostile network for
others; a cloud zone is a private VPC or the public internet depending on how it was drawn.
Guessing either way produces a wrong finding on every asset in that zone. **What would settle it
is a per-zone trust attribute the operator sets** — `scan_zones.trust_level` exists as an integer
nobody has given a meaning to. The next reader will assume `branch`/`cloud` were an oversight;
they were not.

## The one-moderate-key question (carried from session 14): ssh_hostkey stays moderate

Session 14 left a question: a lone SSH host key does not merge under ADR-007's counting, which
strands the common Linux-with-SSH-no-TLS estate. The proposal was that possession demonstrated
during a key exchange might make `ssh_hostkey` *strong*, not the counting wrong.

It was checked and the premise fails in both directions:

- **TLS also proves possession.** `crypto/tls` verifies the `CertificateVerify` signature
  against the presented leaf regardless of `InsecureSkipVerify` (that flag skips chain and
  hostname checks, not the handshake signature). So possession is not special to SSH.
- **Our SSH probe demonstrates nothing.** It abandons the exchange at `KEX_ECDH_REPLY` without
  computing the shared secret or verifying the signature — deliberately, ADR-049's invariant-9
  argument. Ranking the key strong "because possession was demonstrated" would claim something
  the code checks for TLS and does not check for SSH.

And more fundamentally: strength in ADR-007 is about **uniqueness**, not possession. Cloned SSH
host keys in VM templates and container images are common, and are the same defect ADR-007 used
to refuse `mac` as strong. Under moderate, two clones become two assets — recoverable; under
strong, one asset — not. **`ssh_hostkey` stays moderate.** The deferral stands, and its unblocker
is `hostname_domain_os`, already named in `internal/domain/identity.go`. Decided against the
deliverable, not for it: the deliverable passes with two independent moderate keys (a host running
SSH and HTTPS), which is a correct outcome rather than a loosened rule.

## Alternatives considered

**A predicate language now.** Rejected: §2. The engine hosts one when the third same-shaped
evaluator arrives.

**Evaluate inline at ingest.** Rejected for the reason correlation is a sweeper (ADR-026): an
observation is not both complete and visible until the terminal ack, and a rule that failed
inline would take the observation with it. Evaluation runs after correlation, which runs after
promotion.

**One finding per vantage point.** Rejected: ADR-010. It inflates the critical count by the
number of vantage points and fragments remediation.

**Seed the built-in pack at Core startup.** Rejected: the application role cannot write the
knowledge tables (ADR-019), and widening its grant to allow a startup seed is exactly the
posture that read-only stance protects. A migration is the writer that ships with the build.

**Ship the four unbuildable rules as always-passing stubs so the count reads 20.** Rejected as
the gate-that-silently-passes failure: a coverage claim that includes a rule that cannot fire is
worse than an honest 13.
