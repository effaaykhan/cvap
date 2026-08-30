# ADR-027: Engines are separate processes behind a job contract

**Status:** Accepted
**Date:** 2026-08-30

## Context

A Scan Point hosts several engines — discovery, fingerprint, credentialed host, crawler and
DAST, API, config, SAST — with very different maturity, blast radius and resource profiles.
They run inside customer networks, parse hostile input from untrusted targets, and will be
built over a decade rather than a quarter. How they are hosted determines what can be changed
later and what a single engine crash costs.

## Decision

Engines are **separate processes** hosted by the Scan Point runtime, communicating over a job
contract: the runtime hands an engine a job and receives observations back. Engines declare
capabilities and versions, which the Scan Point reports on connect so Core never dispatches
work an engine cannot execute (ADR-022). Engines do not reach the database, do not speak the
dispatch protocol, and do not write assets or findings — they emit observations to the runtime
(ADR-006).

Four consequences of the split are decided here, not left to the runtime's discretion:

- **Rate budget is allocated, not shared.** The runtime owns ADR-024's budget and allocates
  slices to engines, never allocating more in aggregate than the ceiling. Engines report actual
  send counts on a short interval and the runtime reclaims unused allocation. The aggregate is
  bounded **by construction**, not by monitoring, and there is no shared mutable rate state
  across processes.
- **Scope enforcement stays at exactly two sites.** The scan-point-side check of ADR-024 lives
  in the **runtime**, not the engine. Engines receive resolved, pre-authorised targets and may
  not construct new ones; anything discovered mid-scan — a redirect, a DNS answer, a referenced
  host — goes back to the runtime for authorisation before the engine may touch it. Two sites
  regardless of engine count or language, so `make safety`'s "both paths" assertion stays
  valid.
- **Kill switch.** Core→runtime is the network hop; runtime→engine is `SIGTERM` then `SIGKILL`
  after a short grace. Comfortably inside ADR-024's 10-second bound, and it does not depend on
  a wedged engine cooperating.
- **Engines never receive raw credential material.** The runtime holds the credential,
  establishes the authenticated session, and hands the engine a **session handle**. Where that
  is impractical the engine receives a short-lived derived token, never the credential itself
  (ADR-020). New engines register capabilities; the Control Plane does not change.

## Alternatives considered

**Link engines into the Scan Point binary.** The obvious alternative, and genuinely simpler:
one binary to ship, no IPC, no serialisation on the hot path, shared memory for the
fingerprint corpus. Rejected on three grounds, all of them isolation. A crash or memory exhaustion in one engine
— parsing hostile input from an untrusted target — takes down the whole Scan Point including
unrelated in-flight jobs. Per-engine resource limits and credential containment cannot be
enforced within one address space, so a defect in the newest, least-proven engine has the same
reach as the oldest. And a single address space forecloses replacing one engine's
implementation independently: everything must be built from one toolchain, in one language, at
one version, forever.

**Engines as plugins loaded from shared libraries.** Keeps a single process while allowing
independent builds. Rejected: it gives up the crash and resource isolation that motivated the
split while adding ABI compatibility problems across the version skew ADR-022 says is the
normal state.

**Engines as separate network services the Scan Point calls.** Maximum isolation. Rejected as
disproportionate: it means operating a small distributed system inside every customer network,
with service discovery, its own auth and its own failure modes, for components that share a
lifecycle and a host.

**One engine per Scan Point, scaled by deploying more Scan Points.** Clean, and rejected on
deployment cost: a customer with one internal network segment would need six enrolled Scan
Points, six certificates and six upgrade paths to get full coverage.

## Consequences

An engine can be rewritten in another language without touching the runtime, the protocol or
Core — which is the property ADR-001 depends on when it holds Rust in reserve, and which makes
ADR-025's build-versus-consume line enforceable per engine rather than per platform. Those
ADRs rest on this one; this one rests on isolation and crash containment alone. A crashing or
runaway engine costs one job, not the Scan Point. Per-engine resource and rate limits become
enforceable by the operating system rather than by convention.

Credential containment survives the crash path, which is the case this ADR was designed
around: an engine that segfaults on hostile input or is `SIGKILL`ed by the runtime holds a
session handle or a short-lived token, not a reusable secret. **Core dumps are disabled on
engine processes**, and anything that must live in engine memory relies on kernel page-zeroing
at process death — a backstop, not the primary control.

The costs are real: IPC and serialisation between runtime and engine on every job; process
supervision, restart policy and zombie handling in the runtime; a job contract that is now an
internal interface needing versioning of its own as engines and runtime upgrade at different
rates; higher memory floor per Scan Point from running several processes; and a runtime that
has grown into the enforcement point for scope, rate and credentials all at once, making it
the component whose correctness matters most and the one `scan-safety-auditor` must read
hardest.

## Review trigger

Revisit if per-job IPC overhead is measurable against discovery throughput at the ADR-024 rate
ceilings, or if the memory floor makes Scan Points impractical on the small appliance hardware
branch deployments use.
