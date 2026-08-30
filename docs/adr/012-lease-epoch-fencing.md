# ADR-012: Job leases carry monotonic fencing epochs; reassign_safe gates retry

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 used heartbeat-timeout-then-retry, which is at-least-once. For active scanning that is
harmful rather than merely wasteful: a network partition that makes Scan Point A *look* dead
while it is still running means A and B both hit the same production application, doubling
load and defeating the policy's rate limit exactly when the customer is least able to
tolerate it.

## Decision

1. Dispatch assigns a job with a lease carrying an expiry and a **monotonically increasing
   epoch**.
2. The Scan Point renews periodically and **must self-abort and zeroise credentials**
   (ADR-020) if renewal fails, rather than continuing optimistically.
3. Result submission includes the epoch. Results carrying a superseded epoch are **withheld
   from the finding pipeline and surfaced to an operator — never dropped** (ADR-026 defines the
   `ACCEPTED_QUARANTINED` outcome). "Rejected" here has always meant rejected as findings, not
   discarded as data.
4. Reassignment happens only after demonstrable lease expiry, and issues a new epoch.

Jobs carry `reassign_safe`. Passive discovery is safe to duplicate and retries freely. Active
DAST, intrusive checks and anything credentialed that changes state are not: on lease loss
those **fail loudly and surface to an operator** rather than silently retrying.

`reassign_safe` is **orthogonal to `SCAN_POLICY.safety_mode`** (ADR-021). It asks only whether
duplicating this work would harm the target, not whether the checks are aggressive: active
DAST is safe-mode-permitted and not `reassign_safe`, while an intrusive port sweep may well be
`reassign_safe`. It also governs **retry, not retention** — results from a job that lost its
lease are always persisted (ADR-026); `reassign_safe` decides only whether the work re-runs.

## Alternatives considered

**Heartbeat with timeout and retry, no epoch.** The v1 design. Rejected: it cannot distinguish
"worker is dead" from "worker is unreachable", and under partition it produces exactly the
duplicate-execution scenario above. The failure is invisible to us and visible to the customer
as a load spike on production.

**Epochs, but retry everything on lease loss.** Rejected: the epoch prevents *stale results*
from being accepted, but it does not un-send packets. A DAST job that lost its lease
mid-execution may have already submitted destructive-adjacent requests; re-running it doubles
that. Fencing protects data integrity; `reassign_safe` protects the target.

**Fail everything loudly on lease loss, with no retry at all.** Safe but operationally poor —
passive discovery across a /16 would surface operator alerts for ordinary transient network
blips. The `reassign_safe` split puts the strictness where the blast radius is.

**Distributed consensus or a lock service for job ownership.** Correct and far heavier. A
monotonic epoch column in the same database that holds the job state (ADR-003) gives the same
fencing guarantee within one transaction.

## Consequences

Two scan points never concurrently execute one intrusive job, and the rate limit a customer
agreed to is the rate limit they get. Credentials are bounded by lease lifetime, which is
what makes ADR-020's memory-only model meaningful. The costs: `reassign_safe` must be set
correctly per job type or the guarantee is decorative; non-reassign_safe failures become an
operator queue that must be worked; and every result path must carry and check the epoch,
including the locally-buffered results of a scan point that was offline (ADR-026), which will
sometimes be quarantined as stale after a long outage — stored and escalated, not lost.

## Review trigger

Revisit if the operator queue of failed non-reassign_safe jobs is large enough to be ignored
in practice, or if measured lease-loss rate under normal network conditions makes minutes-
bounded jobs (ADR-011) unable to complete.
