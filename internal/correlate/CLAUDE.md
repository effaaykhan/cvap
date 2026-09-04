# internal/correlate

Observations become assets here, and nowhere else (ADR-006).

Rules:

- **The DECISION is pure and lives in `internal/domain`.** This package gathers candidates,
  calls `domain.Resolve`, and applies the verdict. The split is what makes a merge replayable
  over history against a corrected rule — and a merge is the one decision in this system that
  cannot be undone by looking again, because it interleaves two hosts' findings and timelines.
  Do not move a ranking, a threshold or a conflict rule into this package.
- **A sweeper, not an ingest hook.** An observation lands `pending` and is promoted to
  `accepted` by the terminal ack (ADR-026's ratchet), so there is no moment during ingest when
  a submission is both complete and visible. A correlation that failed inline would take the
  observation with it; one that fails here leaves the row unresolved and tries again.
- **The unit is a HOST, not an observation.** Identity is a property of a host and the evidence
  is spread across several observations — the certificate from one, the host key from another,
  the address from all of them. Resolving one at a time hands the merge rule a single key and
  asks it to adjudicate corroboration it cannot see.
- **One transaction per host.** Closing an address interval, opening the new one, recording the
  keys and marking the observations resolved are one decision. A crash between any two of them
  leaves the ambiguous state migration 0031 refuses, or an observation resolved against an
  asset that was never written.
- **A queued verdict leaves the observations UNRESOLVED.** `asset_id IS NULL` is what the
  finding pipeline reads as "not yet correlated", and an item nobody has adjudicated must not
  look correlated.
- Evidence for a merge and for a queue item is **copied**, never referenced: both must outlive
  the observation partition that raised them (ADR-007, ADR-016).

## What an address means

`Open` closes another ASSET's hold on an address, because two assets on one live address makes
every later correlation ambiguous rather than wrong — and ambiguity degrades merge quality
quietly. Migration 0031's partial unique index is the backstop.

It deliberately does **not** close the same asset's other addresses. A multi-homed host holds
two, and a scan that saw one is not evidence the other is gone. `CloseStale` is what closes
them, on the same window that gives `ip_window` its meaning, so `valid_to IS NULL` keeps
meaning "is here now" rather than "was here once".

## What this build can and cannot merge

Two identity keys are reachable from a network scan: `ssh_hostkey` and `service_cert_fp`, both
moderate. Every other key in ADR-007's table needs an agent, cloud metadata, a raw socket or a
probe kind that does not exist — enumerated in `internal/domain/identity.go`.

**One moderate key alone does not merge.** That is ADR-007's rule, not a gap: a host offering
only an SSH host key becomes a new asset when its address changes, because nothing seconds the
key. The common estate — Linux with SSH and no TLS — is exactly this case.
`TestOneModerateKeyAloneDoesNotMergeAcrossAnAddressChange` asserts it so it stays a decision.
