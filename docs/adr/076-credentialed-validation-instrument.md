# ADR-076: The credentialed slice is a measurement instrument; the credential stays in the runtime

**Status:** Accepted
**Date:** 2026-09-10

Implements ADR-075's narrow credentialed slice: Linux over SSH, package inventory only, Ubuntu, as a
validation instrument. This ADR records two design decisions the build forced, one of them a
correction to the session's own instruction.

## The credential stays in the runtime — the instruction was caught, not followed

Session 39's requirement 1 said "this is the first *engine* that actually holds a credential." That
contradicts ADR-027, which is frozen and explicit: **"Engines never receive raw credential material.
The runtime holds the credential… the engine receives a short-lived derived token, never the
credential itself."** ADR-027 even lists a "credentialed host" engine — it anticipated exactly this
work, and it put the credential in the runtime on purpose (per-engine credential containment cannot
be enforced within one address space; a defect in the newest engine would otherwise reach the
credential).

**This was caught rather than followed.** The instruction was wrong and the frozen decision held: the
credential is held by the runtime, not any engine. Everything else requirement 1 asked for applies to
the runtime's holding — just-in-time with the job, scoped to the job's targets, memory-only, the
`func() []byte` pattern of ADR-038 (the `Credential` type in `internal/scanpoint/creds.go`, not a
string), zeroised on completion and on abort. Session 9 proved that zeroise path on lease loss; this
is the first time it holds a credential for a *live authenticated read*, which is the milestone —
located where ADR-027 requires.

The operator confirmed: build it runtime-held, do not amend ADR-027.

## SSH needs credential and network together; the production engine's placement is deferred

Building the read surfaced a tension the frozen ADRs do not resolve. SSH authentication *is* the
credential (or a private key) presented at connection time — there is no "derived token" to hand an
engine (ADR-027's escape hatch assumes one). So the SSH read needs the credential **and** the
network connection co-located. But ADR-027 puts the credential in the runtime, and ADR-047 grants
net-to-target to an *engine* and pointedly not to the runtime. For SSH those two placements collide:
the credential cannot leave the runtime, and net-to-target is not the runtime's to hold.

Resolving that for the **production** credentialed-host engine — an engine that has both, or a
command-proxy where the engine's transport connection is driven by the runtime's authenticated
session — is a real decision with a real security surface, and it is **deferred to full Phase 4**.
This slice does not make it.

Instead, per ADR-075 ("the measurement is the deliverable, not the engine"), this slice is an
**operator-run measurement instrument**, not the fleet scan-point/engine path. The instrument is one
short-lived, operator-invoked process that holds the credential (ADR-038 `Credential`, zeroised on
completion and abort), makes the SSH connection itself, reads `dpkg-query` and `/etc/os-release`,
and computes the measurement. Co-locating credential and network in one operator-run tool for one
measurement is not the fleet architecture and does not set a precedent for it: the tool is not a
hosted engine, is not dispatched to scan points, and its credential handling is the ADR-038
discipline the runtime uses. It runs only against a host in `lab/scope.txt` (non-negotiable #10), and
it establishes evidence without impact — it reads inventory, runs no exploit, writes nothing to the
target (non-negotiable #9).

## What the instrument produces (deliverables 1–4)

- **Observations:** installed packages as `package` observations (the observation type migration 0009
  already defines; the wire carries it) with the distro release `/etc/os-release` reports. That
  release is **exact**, not band-inferred, so it carries a confidence distinct from a band-resolved
  release and **wins over inference** where both exist (the credentialed source outranks ADR-064's
  band vote). engine_kind `host` and `component_source = package_manager` already exist for this.
- **The measurement is the deliverable** — three numbers on the real host: version extraction
  (banner vs installed, per service: right/wrong/absent), release attribution (band vote vs
  `/etc/os-release`), and the §6.2 **FP/FN of the unauthenticated findings against credentialed
  ground truth** — the first accuracy number this project has that is not measured against a lab
  target built to be found.
- **No tuning against the measurement this session.** A banner-inference error found is a finding and
  goes to the backlog, not a fix — measuring and then correcting against the same sample is what the
  corpus gate (§5.5) forbids.

## Consequences

- New code lives in an instrument, not the fleet path: parsers (`dpkg-query`, `/etc/os-release`), the
  `package` observation shape, and the FP/FN comparison are pure and fixture-tested; the SSH read is
  the only host-dependent part, so the measurement is a command pointed at a host, not code written
  once the host exists.
- The production credentialed-host engine (SSH cred+net placement, WinRM, the domain) remains full
  Phase 4, held behind ADR-075's trigger. This slice deliberately does not build it.
- Reviewed by `security-reviewer` and `scan-safety-auditor` before it authenticates to any real host.
