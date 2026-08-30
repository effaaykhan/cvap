# ADR-023: Compose first; Kubernetes deferred

**Status:** Accepted
**Date:** 2026-08-30

## Context

Deployment targets range from a lab or small organisation on one machine to a large SaaS
estate. On-prem customers install this themselves, in environments we cannot observe, and
many of them do not run Kubernetes or do not want a vendor's workload on the cluster they do
run. The deployment substrate chosen first shapes every operational assumption in the
codebase.

## Decision

Single-node Docker Compose is the primary deployment target and the one every developer and
lab runs. VM or multi-node Compose covers mid-market. Kubernetes is supported for large SaaS
and is scheduled with scale and HA work in Phase 12. **Kubernetes is never mandatory.** The
application makes no assumption that it is running under an orchestrator.

## Alternatives considered

**Kubernetes-first, with Compose generated or unsupported.** The default answer for a modern
distributed system. Rejected on the customer side — it imposes a cluster on on-prem buyers
who do not have one, and turns installation into a consulting engagement — and on the
development side, where it makes the local loop and the lab environment substantially slower
for a team that has not yet shipped Phase 1.

**Compose only, forever.** Rejected: it does not carry the large SaaS deployment, where
rolling updates, autoscaling and multi-zone availability are genuinely wanted. Deferring
Kubernetes is not the same as refusing it.

**Ship a single-binary install with no containers at all.** Attractive given Go's static
binaries (ADR-001), and it remains viable for the Scan Point, which ships as an archive of a
runtime binary plus engine binaries (ADR-027) with nothing to install. Rejected for Core,
which needs Postgres, an object store and Redis alongside it — orchestrating those on a bare
VM by hand is worse than Compose, not better.

**Vendor-managed cloud services (RDS, S3, ElastiCache) as the baseline.** Rejected: it
excludes on-prem and air-gapped deployments outright, which ADR-017 commits to serving.

## Consequences

The install is `docker compose up` for the majority of deployments, which keeps the on-prem
support cost and the sales objection low, and it makes `make lab-up` a realistic
representation of production. Component choices stay portable — S3-compatible rather than S3
(ADR-015), self-hosted Postgres (ADR-002). The costs: HA and rolling updates are absent until
Phase 12, so early deployments accept downtime for upgrades; and the codebase must avoid
depending on orchestrator-provided service discovery, secret injection or health management,
providing its own instead.

## Review trigger

Before Phase 12, and immediately if a design partner's scale or availability requirement
cannot be met by multi-node Compose on VMs.
