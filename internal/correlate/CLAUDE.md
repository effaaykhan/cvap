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
  look correlated. The park is scoped to the ADDRESS, not to the sweep's batch (ADR-096): every
  sighting short of a merge at an address with a pending item naming the asset waits with it, the
  occupant's own included — the batch-bounded version let a contested host's overflow attach to
  the occupant one sweep later (phase-session-map §5.15), and the weak-only version was defeated
  by echoing one of the occupant's public SSH fingerprint (B44). The park holds only while the
  contest is FRESH (`domain.ContestFresh`: a key the asset does not hold was parked there inside
  the window — a key of a held type from the same port with a DIFFERENT value, never a key the
  asset merely has not recorded); a stale contest expires on the next agreeing sighting — items
  closed `expired`, `identity.contest_expired` written — because a park with no expiry is a denial
  of service with a one-packet trigger. Expired evidence STAYS OUT of the sweep (`ListUnresolved`
  excludes pending, expired and discarded items): released, it re-parked itself with a fresh
  timestamp and renewed the freeze for ever. A FRESHLY contested address does not age out:
  `CloseStale` skips an address with an item parked inside the window AND `domain.Resolve` treats a
  fresh contest as extending the hold — or the contradicting host (or the returning occupant)
  becomes a new asset there; a stale one ages out like any other silence, or a dead occupant's
  address is held for ever. An occupant whose key has not answered for a full window while the
  newcomer answered on two scans has LAPSED: the newcomer is a new asset whose keys are recorded
  `lapsed` — inventory, never the trust root, because against a live host that lost only tcp/22 the
  lapse is the terminal state of every contest that survives a window — and the occupant's items
  expire. The ageing pass runs BEFORE the sweep's nothing-to-do return: a tenant
  whose every observation is parked has nothing unresolved and everything to age. A park is
  announced — `identity.contested` keyed to the asset, per sweep that parks something new — and
  counted on Health.
- **A contested address is asked twice, and the second question is measured.** When
  `domain.Resolve` queues a handover it names the contradicting keys (`Verdict.Handover`);
  `continuityFor` then measures ADR-096's four facts (distinct scans that saw the key here, the
  held key's last sighting, product continuity, OS family) and Resolve is called again with them
  on the candidate. The thresholds and the outcome are domain's; this package only reads. A
  rotation attach retires the held key, records the new one with `rotation` provenance — which
  the credentialed trust root EXCLUDES until an operator pins or confirms it, because a takeover
  of the SSH port alone is indistinguishable from a rotation on banner data — closes the parked
  items carrying the classified keys as `rotated` and lets the parked observations back into the
  sweep. Every input is public banner data: continuity narrows the window and verifies nothing,
  so the inventory moves and the trust does not.
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
