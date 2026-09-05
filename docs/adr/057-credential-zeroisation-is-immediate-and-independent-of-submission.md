# ADR-057: Credential zeroisation is immediate and independent of submission

**Status:** Accepted
**Date:** 2026-09-05

## Context

A scan point's terminal path does two things when a job ends: it zeroises the job's credential
material (ADR-020 — credentials are memory-only and must not outlive the job) and it submits
what the job gathered (ADR-026 — results are always submitted, never discarded). Session 20's
graceful-shutdown work put these next to each other and raised the ordering question directly:
the submission drain can block for a long time against an unreachable Core, and the code
already zeroises *before* it, with the comment "credential lifetime must not be tied to how long
an upload takes."

The question has never actually bound, because **no engine holds a credential yet** —
credentialed assessment is out of the MVP scope (execution-plan §2), so no submission carries a
value derived from a credential and nothing about zeroisation timing changes what gets sent.
Credentialed assessment (Phase 4) is the first thing that changes that. Deciding the ordering now,
cheaply, is better than deciding it under pressure in the session that introduces the first
engine that authenticates.

## Decision

**Zeroisation is immediate and independent of submission.** When a job reaches any terminal
state — completion, lease loss, cancellation, kill, engine failure — its credentials are
zeroised at once, and that does not wait for, depend on, or interleave with the result upload.
The credential is not needed to upload results (the payload comes from the engine host, not the
credential), and holding it live across a drain that may block for minutes against an unreachable
Core is exactly the exposure window ADR-020 exists to bound. The upload's duration must never
extend a credential's lifetime.

**If a submission ever needs a value derived from the credential, that derivation happens
before the zeroise, and the derived value — not the credential — is carried into the
submission.** Deriving after zeroise is impossible (the material is gone); holding the credential
until submission is what this decision refuses. So the order for a credentialed job is: stop the
engine, **derive whatever the submission needs from the credential**, zeroise, then assemble and
submit from the (now credential-free) derived value plus the engine's results.

## The finding: the code cannot express this split yet

The current terminal path expresses the *first* half correctly and has no seam for the second:

- Every terminal path funnels through `runtime.terminate()`, whose **first action is
  `j.zeroiseCredentials()`** — before it gathers results or assembles anything. `abort()`
  zeroises once more before calling it. So zeroise is unambiguously before submit. Good.
- But the submission is built **entirely from the engine host** (`host.results()` → `toWire`),
  which never reads the credential. There is nowhere a credential-derived submission value is
  computed, and no slot before the zeroise to compute one. The derivation-before-zeroise step
  the decision above names **does not exist**.

This is harmless today — nothing is derived, so there is nothing to lose to an early zeroise. It
stops being harmless the moment a credentialed engine's submission must carry a credential-derived
value (a proof-of-access nonce, a session identifier, an authenticated-check attestation). At
that point the terminal path needs a real change: a derive step before `terminate()`'s zeroise,
with its output carried into the submission — not a slot filled, because zeroise is currently
first by construction. Recording it here makes that a **scheduled, pre-decided change** rather
than one argued under pressure in Phase 4, which is the whole reason for deciding now.

## Alternatives considered

**Hold the credential until submission completes.** The obvious way to let a submission use a
credential-derived value: keep the credential live through the upload. Rejected — it ties
credential lifetime to how long a drain against an unreachable Core takes, which can be minutes
and is the precise exposure ADR-020 bounds. A credential that outlives its job because the network
was slow is the failure the memory-only rule exists to prevent.

**Derive after zeroise.** Not an alternative so much as an impossibility: the material is gone.
Named only to close it off, because "we'll compute it when we build the submission" is the
natural place to reach for and it is too late by then.

**Leave it for Phase 4.** Rejected on the reasoning in the Context: the constraint is cheap to
decide while it does not bind and expensive to decide while it does. The code change is deferred;
the decision is not.

## Consequences

The rule is now settled before it binds: a credentialed engine's terminal path derives from the
credential first, zeroises immediately, and submits from the derived value — the credential never
lives across the drain. Until credentialed assessment exists, the code keeps its current shape
(zeroise first in `terminate()`), and a comment there points at this ADR so the derive-before-
zeroise seam is added deliberately rather than discovered. The gap is named in the scan point's
terminal-path code, not left for the Phase 4 author to infer from ADR-020 and ADR-026 separately.

## Review trigger

The first engine that authenticates — the first credentialed assessment. Concretely, the first
submission field whose value must be derived from a credential. That is the change that adds the
derive-before-zeroise step this ADR pre-decides, and it is the point to confirm the derived value
carried forward is not itself credential-shaped (a bearer token derived from a credential is a
credential, and gets the same memory-only, zeroised treatment, ADR-038).
