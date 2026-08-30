# ADR-007: Asset identity by ranked keys with retained merge evidence

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 stated that assets are identified by something other than IP, but gave no mechanism.
Without one, correlation is guesswork: identifiers available in the field vary wildly in
reliability, and a wrong merge silently fuses two customers' hosts into one asset record with
no way to tell afterwards that it happened.

## Decision

Identity keys are ranked by strength. **Strong (3):** agent-issued UUID, cloud instance ID,
DMI system UUID, TPM or host certificate fingerprint. **Moderate (2):** SSH host key
fingerprint, stable service certificate fingerprint, hostname + domain + consistent OS
fingerprint. **Weak (1):** MAC address, NetBIOS name, IP within a time window. A merge
requires one strong key, or corroborating agreement among weaker ones. IP alone never merges.
Every merge records the observation that justified it in
`ASSET_IDENTITY_KEY.merge_evidence_observation`, **and copies that observation's payload into
the identity key row at merge time**. Merge evidence is a distinct retention class from bulk
observations: it must outlive the 90-day observation window (ADR-016), and copying rather than
pinning the source partition is what lets ADR-016 keep pruning by partition drop. Conflicting
or insufficient evidence sends the observation to an unresolved queue for operator review
rather than guessing.

## Alternatives considered

**Merge on IP, or on IP plus hostname.** The naive default. Rejected: DHCP, NAT, ephemeral
cloud addressing and reused private ranges make IP a time-bounded relationship, not an
identity (ADR-008).

**Treat MAC as a strong key.** Superficially attractive — it looks hardware-bound. Rejected
deliberately: MAC is virtualised, randomised by default on modern client operating systems,
and duplicated wholesale across VM template clones. Ranking it strong would merge every host
built from the same image into one asset.

**Guess on ambiguity and let operators correct later.** Rejected because a wrong merge
corrupts history — findings, exposures and timelines from two hosts are interleaved, and
after the fact nobody can tell which is which. The unresolved queue costs operator attention;
a wrong merge costs trust in the inventory.

**Fingerprint-similarity or probabilistic entity resolution.** Powerful and opaque. Rejected
for v1: an inventory the customer cannot audit is one they will not trust, and ranked keys
with recorded evidence produce a merge decision a human can check in one screen.

**Pin the observation partition against pruning instead of copying the payload.** Keeps one
copy of the evidence and avoids denormalisation. Rejected: a single merge would hold an entire
month's observation partition alive, so pruning would stall on the oldest surviving merge and
ADR-016's partition-drop mechanism would degrade to a bulk delete. The copy is small and
bounded; the pin is unbounded.

## Consequences

Merges stay reversible for the life of the asset, not merely for the life of the observation
partition, because the justifying payload is copied at merge time. Identity quality degrades
gracefully rather than catastrophically as available keys weaken. The costs: an unresolved
queue is a real operational surface that needs UI and someone to work it; estates with no
agent, no cloud metadata and no TLS will accumulate duplicate assets that only better key
coverage fixes; and the copied payload is duplicated data that must be redacted to the same
standard as the observation it came from, since it now outlives the retention window that
would otherwise have removed it.

## Review trigger

Revisit when the unresolved queue rate in a design partner's estate exceeds what an operator
will realistically triage, or when a new identifier class (a hypervisor-issued ID, an EDR
agent ID) is common enough in the field to warrant a place in the ranking.
