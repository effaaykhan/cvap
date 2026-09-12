# ADR-096: A key rotation with service continuity attaches; continuity narrows the window and verifies nothing

**Status:** Accepted
**Date:** 2026-09-12
**Amends:** ADR-094 (frozen), which queues every same-service SSH host-key contradiction at a held
address and said in its own closing section that a host rotating its key is parked and stays parked;
and ADR-091 §4's observed-trust source (frozen) for one provenance — a key recorded by a rotation is
excluded from it until an operator confirms.
**Closes:** B41 (both steps). Records B43 as the reason the classification runs on banners alone.

## What was measured

ADR-094's security re-review rotated a lab host's SSH key and scanned it three times. Every sighting
after the rotation parked: the service row froze at the pre-rotation version, three observations sat
unresolved, four queue items sat pending, no finding was derived, and nothing announced it — the only
trace was a WARN line in Core's log. `PendingCount` existed and had no caller. Under the target's
control: rotate once, vanish from the inventory. A reimage or `ssh-keygen -A` produces exactly the
shape ADR-094 queues, and it is the common case; a different host on a reused lease is the rare one.

The two fingerprint sweeps ADR-094 required were also run and timed for this decision (about two
minutes each, some fifty seconds of it dispatch latency). What they felt like was the finding: blind.
An operator who ran them saw nothing on any screen that said a host was parked, or why.

## Decision

Two steps, in this order, both landed.

### Step 1 — a park is announced, and counted

1. Correlation writes one `identity.contested` audit event keyed to the contested asset
   (`resource_type: asset`, the first candidate) — the key an asset timeline reads by, and B39's
   remedy now names that read, since no route lists an asset's events yet — carrying the address, the verdict's reason, the candidate asset ids, how many
   observations this sweep parked and the last observed time. It is written only when the sweep
   parked something **new**: `ResolutionQueue.Enqueue` reports whether it inserted, and a re-sweep
   of an already-parked group is a no-op that raises nothing. A contested host observed again on a
   later scan inserts new items and raises again. The bound is one event per sweep that parks
   something new at the address; in the common case that is one per contested address per scan
   (measured), and a scan whose observations of the address land across two sweeps raises two.
2. **The park is scoped to the address, not to the sweep's batch.** The security review measured a
   contested host answering on more ports than one sweep's batch holds: the overflow re-grouped
   alone next sweep, carried nothing but the address, found the occupant as its only candidate and
   attached — the newcomer's services written onto the occupant through the door the park exists to
   close. `domain.Resolve` now queues **every sighting short of a merge** at an address that already
   has a pending item naming the asset (`Candidate.PendingContested`, read from the queue by
   address) — the occupant's own sightings included. The first draft let one agreeing key through so
   the occupant's address was not frozen; the review defeated that by echoing one of the occupant's
   public fingerprints beside the newcomer's services, because the fingerprint probe verifies no
   possession for SSH (B44). So a contested address is contested for everyone **while the contest is
   fresh** — while a contradicting key has been parked there inside the window — and it accumulates
   one item per key per scan and one announcement per scan meanwhile: the bounded, visible failure,
   chosen over the silent one. A merge-grade agreement (ADR-007's bar: a strong key, or two
   independent moderate keys) still proceeds; that is B40's exposure, unchanged here.
   **The contest expires.** A park with no expiry was measured as a detection denial of service with
   a one-packet trigger: one drive-by contradiction froze an SSH-only host for ever. A
   *contradiction* is what `domain.Resolve` calls one at the held address — a key of a type the asset
   holds live from the same port, with a different value, **certificates carved out** exactly as the
   decision carves them out (a renewal is the same host, ADR-094) — and nothing else: a key the asset
   has merely never recorded (TLS the occupant enabled after the park, a second sshd) contradicts
   nothing, and a renewed certificate parked with the group contradicts nothing. The first draft's
   "not held" predicate was measured freezing an occupant on its own certificate for six weeks; the
   second draft's "different value, same port" was measured doing the same on a renewal. The read
   names the exclusions (`ip_window`, `service_cert_fp`) rather than `= ssh_hostkey`, so a strong key
   type this build cannot yet observe still counts; and a key the asset itself holds live is never a
   contradiction, whatever else it holds. **Two values of one key type from one service in one scan
   — two sshds answering on 22 — is two hosts**, and two hosts are never one asset: `domain.Resolve`
   queues such a group before scoring any candidate, with whatever candidates there are, possibly
   none (migration 0045 drops the "at least one candidate" CHECK; an item naming nobody reads
   "unplaceable"), and a partial unique index — one live key per (asset, type, port, protocol), the
   key's Source — is the backstop no caller can get past. The review measured the alternative: both keys recorded on one
   asset, after which the asset's own key contradicted its other key on every scan and the park
   never expired. An item naming nobody is outside every other transition (each is keyed on the
   asset it names), so it expires absolutely one window after it was parked: nothing is lost, nobody
   was ever going to be chosen (measured: two such items pending for sixty days with the Health chip
   amber and two more per scan). The same absolute expiry covers a pending item none of whose
   candidates still holds its address: the occupant aged out and another host took the address, and
   every other close is keyed on the named asset attaching *there*, which it never will (measured
   pending for ever otherwise). The ageing pass — stale intervals, stale items — runs at most once an
   hour per tenant (`correlate.AgeingInterval`): a seven-day window does not need thirty-second
   ageing, and per-sweep ageing measured ten seconds of a thirty-second sweep at the dev database's
   tenant count. What it expires it announces (`identity.items_expired`, the addresses) — a
   close-out nothing records is a refusal that vanished, and B39's verb should find in the log why
   an item it could have acted on is gone. **The one contest with no automatic exit** is two values
   of one key type on one port at a held address: it is refused before any candidate is scored, so
   neither the rotation nor the lapse can reach it, and its parked items are contradictions that keep
   it fresh for as long as the two keys keep answering — one packet per scan. Bounded and visible,
   like the rest, but the only shape whose exit is B39 alone; stated so it is not read as an
   oversight. More generally, **a contradictor who keeps presenting keeps the address contested**:
   the fresh contest holds the interval, the held interval keeps the items reachable, and neither
   ages while the other stands. That is deliberate. A cap on the hold was measured and rejected —
   after the cap the newcomer becomes a plain new asset with trusting provenance, which turns "hold
   tcp/22 for k windows" into the trust root against a live host, the outcome every other rule here
   refuses. The price of a persistent contradictor is a frozen, announced inventory and a queue that
   grows one item per parked key per scan; the reward is never a credential. B39 is the exit. When
   no contradiction has been parked at the address for a full window (`ContradictionLastSeen`, read
   from the queue; `domain.ContestFresh` decides), the next sighting the address holder's own evidence
   agrees with attaches, every pending item at the address naming the asset closes as `expired`
   (`resolved_by` NULL, no asset chosen) and an `identity.contest_expired` event is written. **Expired
   evidence stays out of the sweep**: the first draft released it, and the same contradicting
   observation re-parked itself on the next pass with a fresh timestamp — one packet, a freeze renewed
   for ever (measured). Only a `rotated` close, or an operator's verb (B39), releases parked
   observations; an expired park's observations stay unresolved and are **not re-derived** — what
   the host still answers is re-derived by the sighting that attached; a port that answered only
   during the freeze is gone — which the seven-day unresolved count carries until they age out of
   it, and which the `identity.contest_expired` event says in as many words. A newcomer who keeps contradicting keeps the contest fresh
   — and is then either classified (step 2) or waits for B39; one who leaves loses the freeze after a
   window, and must present the contradiction again to renew it.
3. **A freshly contested address does not age out; a stale one does.** A park touches no address
   interval, so the occupant's hold would lapse after the window and the contradicting host's next
   sighting — no candidate by key, none by address — would become a *new asset* there, with a key the
   trust root does not exclude; and an occupant returning after the window would split into a
   keyless twin of itself. The review measured both: seven days of waiting was cheaper than passing
   the classification. Two sites, because a row that survives is not a decision that reads it:
   `CloseStale` leaves an address alone while an item **parked inside the window** names its holder,
   and `domain.Resolve` treats a **fresh** contest (`ContestFresh`) as extending the hold — the
   address-holder branch (handover, rotation, contest) runs whether or not the interval is inside the
   window. Bounded by freshness on both sites, because an unbounded hold was measured keeping a dead
   occupant's address for ever: a genuine host on a reused lease never inventoried (the gone
   occupant's products can never be continuous again), and a third host attaching to the dead asset
   on the address alone. A stale park ages out like any other silence, and the ageing pass runs
   before the sweep's nothing-to-do return — a tenant whose every observation is parked has nothing
   unresolved and everything to age (measured: a frozen host never aged).
   **The occupant can lapse while the newcomer stays.** A bare handover — nothing of the occupant
   agreeing — whose held key has not answered at the address for a full window, **whose interval is
   outside the window too**, and whose newcomer key answered on two distinct scans and is held live
   nowhere else, is ADR-094's aged-out address with the contest as witness: the newcomer becomes a
   **new asset**, the occupant's interval closes under it, the occupant's items at the address expire
   (`identity.contest_expired` names both assets) — and the newcomer's keys are recorded with
   provenance **`lapsed`**, which the credentialed trust root excludes exactly as it excludes
   `rotation`. A lapse moves the inventory and never the trust. It cannot: a fresh contest parks every
   sighting of the occupant, so its interval and its service rows freeze, and one window later the
   lapse is the terminal state of *every* contest that survives a window — against a live host that
   lost only tcp/22 as much as against a dead one. The review measured the first draft's `new_asset`
   provenance buying the trust root with one window of holding tcp/22 while the victim answered
   tcp/80 every day: cheaper than the rotation it preempted, and the cruder forgery (not bothering to
   mimic the banner) bought *more* than the careful one. Against a live host ADR-094's "wait for the
   address to lapse" price is unpayable — every keyless sighting renews the hold — so the contest is
   what made it payable, and the lapse must not pay out. The earlier draft that tested only the key's
   sighting was measured evicting a live occupant whose SSH key had last been fingerprinted nine days
   earlier (an occasional intrusive pass, the normal state of ADR-093's hosts) in three scans of
   tcp/22. The lapse is a scored outcome, ordered after a contest and a merge:
   a mover whose keys another asset holds at merge grade is that asset's, and the lapsed holder is
   evicted by the merge, not duplicated by a keyless new asset (measured). The second depends on the first (the holder is found by its
   live interval), so the first must be exact: the queue item carries a normalised `address inet`
   (migration 0045, written once by `Enqueue`, backfilled for older rows) and every by-address read
   compares inet to inet — the first draft compared the copied payload's text to the canonical
   rendering, and a non-canonical spelling (`010`, an unabbreviated IPv6) aged the occupant out and
   handed the address, and the trust root, to the newcomer (measured). inet equality also carries the
   mask — `10.44.3.10/24` and `10.44.3.10` were two live rows on two assets under migration 0031's
   unique index (measured) — so correlation now canonicalises every payload address at the group
   boundary with `netip` (strict: no leading zeros, no mask; a zone — which `netip` accepts and
   `inet` does not — is refused explicitly, because a group the store cannot write was measured
   pinning the head of the batch for the whole tenant; one rendering; what is refused is left
   unresolved like a missing address), the address writes (`Open`, `Enqueue`, the sighting)
   store the bare host so no other caller can reintroduce a masked spelling, the by-address readers
   normalise their argument the same way, and migration 0045
   rewrites any masked row already in `asset_addresses`, the sightings and the queue's backfill bare
   (a masked duplicate of a bare live row is closed — it was never the row being read). An address with nothing
   pending ages out exactly as
   ADR-094 says, and a host first seen there afterwards is a new asset with ADR-094's two-scan trust:
   an attacker who never contradicts and simply waits for the occupant's address to lapse pays
   ADR-094's price, not this ADR's, and this ADR makes that neither cheaper nor dearer.
4. Health carries `resolution_queue_pending` (items — several per host per scan) and
   `contested_addresses` (distinct normalised addresses with a pending item — the number an operator
   acts on; items parked before ADR-094 with an empty payload were backfilled from their key value
   and count). The console renders both, amber when either is non-zero.
5. **Dropped, not deferred:** the first draft of B41 proposed deriving services (not identity) for a
   contested group so the parked host's inventory kept moving. That is the back door the ADR-094
   reviews closed — a newcomer's banner would move the occupant's service rows and findings while its
   identity is contested, which is the wrong-merge outcome under another name. A parked host is
   visible now. It is still parked, until step 2 or an operator (B39) resolves it.

### Step 2 — a contradiction that classifies as a rotation attaches

`domain.Resolve` keeps its rule; it gains one input and one branch. The address-holding candidate
may carry a `Continuity` — facts correlation measured about this address on this scan — and a
same-service SSH host-key contradiction at the held address **attaches as a rotation** when every
one of these holds. It is classified before the not-outvoted guard, so the shape with a steady
certificate agreeing beside the rotated key (`ssh-keygen -A` on a TLS host) qualifies as well as
the bare handover; the guard is about outvoting, and this is a second question asked with facts
the first pass did not have:

| Fact | Threshold | Where it is measured |
|---|---|---|
| The newcomer key has been seen at this address on distinct scans | at least **2**, this scan included (`domain.RotationScans`) | pending queue items for the key at the address, joined to the observations' scans, inside `store.SightingWindow` (7 days, the address window) |
| The held key has answered at the address on none of them | the held key of that service **has a sighting on record** at (address, port) and it is **before** the newcomer's first; a held key with no sighting here (recorded before migration 0044, or first seen on another port — B42) does not pass, and the held key **agreeing on this very scan** — two keys answering on one port — is never a rotation | `asset_identity_key_sightings` (written on attach) **and** the queue (a park writes no sighting row, so the held key's parked sightings at the address and port count too), and the agreeing set of this scan |
| Every previously seen product still answers on its port | every service row the asset holds with a product, last seen inside the window, is observed in this sweep's group for the address at the same port and protocol with the **same product** (case-insensitive; where one port carries two observations the later one is compared); an asset with **no product on record** has nothing to be continuous with and does not pass | `services` against the group's service observations — the group is what this sweep holds for the address, so a scan whose observations of one address land across two sweeps parks rather than classifies |
| The OS attribution agrees | the asset's distro **family** equals the family the group's banner hints attribute; an asset with no family imposes nothing; a group with no hint against an asset with a family does not agree | `assets.distro_family` against `domain.AttributeOS` over the group |

Anything short of all four queues exactly as ADR-094 does. Only SSH host-key contradictions are
classifiable: a contradiction of any other type at the held address (a strong key this build cannot
yet observe, say) is never forgiven by banner continuity. Two contradicting keys on **one** port never
classify: the measurement is per service, and judging both on one key's two-scan history was
measured rotating a one-scan key in (and the apply path retiring the first key it had just
recorded).

The **release** is deliberately not compared. A reimage commonly moves a host from one release of the
same family to the next; that is a rotation the operator wants attached, not a different machine.
The asset's exact release (ADR-095) stays where it is, its age visible, until the next credentialed
read replaces it.

What the attach writes, in the host's one transaction:

- the held SSH host key on that port is **retired** (`valid_to`), and the newcomer's is recorded with
  provenance `rotation` — which the credentialed trust root **excludes** for as long as it carries
  that provenance (next section); the credentialed engine never dials on a rotation's say-so;
- a renewed certificate beside the rotated key is **not** replaced by the rotation. The four facts
  are about the SSH key, the products and the OS, and measured nothing about the certificate;
  replacing it here would hand a host that changed both its key and its certificate two moderate
  keys on the asset with no corroboration at all — `mergeRule`'s bar at any address the attacker
  controls (measured). It stays `Contradicted`, under the same establishment gate every renewal
  takes (ADR-094) — and **a rotation or lapsed key never establishes**, however many scans see it,
  exactly as it never becomes the trust root: the review measured a rotation key, withheld from
  the trust root, reaching two sightings on a scan where the attacker withheld 443 and then
  corroborating its own certificate against the victim's, which left two moderate keys of trusting
  provenance on the victim's asset and merged the attacker's own address onto it. So a host that
  rotated keeps its old certificate *key* until an operator confirms the rotation (B39); the service
  row carries the new certificate regardless (`services.tls` is replaced on every newer sighting),
  so certificate findings see the renewal. Measured, and stated so it is not read as a bug;
- the pending items at this address that name this asset and that the rotation **examined** — the
  rotated key, the forgiven certificate, a key the asset holds live (a park enqueues every key in the
  group, agreeing ones included, and an item nothing can ever close would keep the address contested
  forever — measured), and the address-only items whose park carried no keyed item left unexamined
  (the classified keys' siblings, and the keyless stragglers parked on the address alone) — are
  closed as `rotated` (`resolved_asset_id` set — migration 0045 requires it, as `merged`
  is required to carry one; `resolved_by` NULL, the system closed them, no operator chose), which
  releases the parked observations back into the sweep; they attach on the next pass, because the
  key they carry is now the one the asset holds. An item parked for a *different* key at the same
  address stays pending. Nothing that was parked is lost;
- a key is lifted from a service observation only when its copied payload carries an exact `port`
  key: the store reads the port back with an exact jsonb key (`Retire`, the held key's sighting,
  the one-live-key-per-service index) while Go decodes names case-insensitively, and a payload
  spelling it `Port` was measured yielding a key nothing could ever retire or contradict; the
  protocol has one grammar on the identity path (absent or `tcp` in any case is tcp; `udp` and
  `sctp` are themselves; anything else lifts no key), because the index mirrors the key's Source —
  port and protocol — and a spelling the index refused was measured retrying the group for ever
  with no asset, no item and no signal; the service row's
  `last_seen` is monotonic and its content moves only with a sighting at least as new, so a parked
  observation released after a later scan can neither drag the continuity input backwards nor put
  older banners under a newer timestamp;
- an `identity.rotated` audit event keyed to the asset names the address, the retired and recorded
  keys and how many items closed — and each step is checked: a held key the retire statement does
  not find, or a recorded key that is not live on this asset afterwards (the key row is unique per
  live value), is a fault that rolls the attach back rather than an event that asserts it; a contradiction that fails the classification queues
  with the four facts as measured in its reason, so the operator (B39) sees which one failed.

Migration 0045 adds the two enum values (`identity_key_provenance` `rotation`, `resolution_state`
`rotated`) so the outcome is recorded in its own word rather than borrowing `attach` or `merged`
(its down migration *retires* rotation-recorded keys before relabelling them, so a rollback and
re-upgrade cannot promote one to trust material),
the `rotated_has_asset` CHECK, the normalised `address inet` column with its backfill, and a partial
index on it for the by-address reads every sweep of a held address, every `CloseStale` and every
Health call now make.

## What continuity buys, and what it does not

Every input to the classification is public banner data. The SSH fingerprint probe verifies no
signature; the product on a port is what the port said; the OS hint is a substring of a banner.

**The real cost of a false rotation is: control the SSH port at the address across two scans.
Nothing else.** The first draft of this section priced it higher — the occupant silent, every port
reproduced, the OS hint copied — and the security review measured that none of it was required: an
attacker who takes only tcp/22 (an on-path redirect of one port, a rogue daemon on a rebound
socket) while the host keeps answering 443 with its own certificate satisfies service continuity
*with the victim's own banners*, because the continuity facts are measured over everything that
answered at the address, and the victim is part of that. On banner data, a single-port takeover of
sshd is indistinguishable from a real key rotation. That is not a gap in the thresholds; it is what
"verifies nothing" means.

So the classification is allowed to move the **inventory** — the host stops being a frozen row and
a growing queue — and is not allowed to move the **trust**:

- **A rotation-recorded key is never the credentialed trust root on its own.**
  `SSHHostKeyFingerprintsAt` excludes `provenance = 'rotation'` however many scans have seen the key
  since. A contradiction of the held key is exactly the signal ADR-091's observed trust root exists
  to catch, and it must not be re-rooted by the mechanism that observed it. Until an operator pins
  the new key (ADR-091 §4, `operator` lines win outright) or confirms the rotation (a B39 verb),
  every credentialed job at that host refuses for want of trust material — the same refusal as a
  host never seen twice. The rotated key does accumulate sightings, so a confirmation is one step
  away, and the audit event says so.
- The held key's history is read from the **same sources as the newcomer's** — the sighting table
  and the queue — because a scan that parks writes no sighting row, and a held key that answered
  during a parked scan is exactly the case the "on none since" fact exists to see. The review
  measured the first draft missing it. A held key with no sighting on record here does not pass; a
  held key answering on the very scan being classified (two keys on one port) never classifies.
- A newcomer key already live on another asset never classifies: the rotation would retire the
  held key and record nothing (the key row is unique per live value), leaving the asset keyless —
  measured. That shape is ADR-094's "enrolled elsewhere" and B40's merge question.

What remains true: ADR-094 narrowed the window from "time one scan" to "persist across two at the
address"; this rule narrows it again to "persist across two on the SSH port, with the rest of the
host still answering as before". Two narrowing mechanisms stacked still verify nothing. What they
change is the cost of the attack and the number of scans an operator has to notice it in — not
whether it succeeds — and what the attack now wins is an inventory row, not a credential. The
operator pin remains the only verification of an SSH host key CVAP has, and the merge rule's own
exposure to planted keys is unchanged and still B40.

Two more things the table does not say. Against an adversary holding tcp/22, the OS fact is not a
narrowing at all: the family this scan's banners attribute is led by the SSH banner, and a
network-only asset's held family came from the same banner on an earlier scan, so the holder of the
port sets both sides. And a service observation whose payload spells the port other than as an exact
`port` key lifts no identity key but still derives a service row — conservative for trust, permissive
for inventory; refusing such payloads at ingest is the cleaner answer and is noted for B44's
neighbourhood.

What the rule does protect against, and was written for, is the common non-adversarial case: the
host that was reimaged on Tuesday and would otherwise be a frozen row and a growing queue until
somebody found the WARN line.

## Why the facts are measured in correlate and decided in domain

The same split as every identity decision (ADR-006, `internal/correlate/CLAUDE.md`): correlation
gathers **data** and hands it to `domain.Resolve` as a `Continuity` on the candidate — per
contradicting service, the distinct scans that saw the new key here and the held key's sighting
here; the asset's products inside the window and this scan's; the asset's family and the family
this scan's banners attribute. Every rule that turns that data into the four facts — the scan
threshold, the sighting comparison and its fail-closed on a missing sighting, the product match and
the "no product on record does not pass", the three-way OS agreement, the "SSH only" restriction,
the "held key agreeing on this scan" refusal — lives in `domain`, where it is replayable over history
against a corrected rule and where the next caller cannot forget it. Correlation asks the second
question only when the first verdict named exactly one candidate — a handover against two assets
is the ambiguous shape ADR-007 queues outright, and it stays queued. The first draft computed three
of the four facts as booleans in correlate; the ADR compliance review pointed out that a replay
against a corrected rule would then reach the old answer, which is the thing the split exists to
prevent. Correlation measures only after a first `Resolve` has returned a handover
(`Verdict.Handover` names the contradicting keys), so a host that is not contested pays nothing for
the rule. The scan occasion is read through the parked item's observation — a soft reference, read
inside the sighting window on purpose, which is why an item whose observation has aged out counts
for nothing; the item itself still outlives the observation, as ADR-007 and ADR-016 require.

## Why not

- **Trust on first use for the new key.** Rejected by ADR-094 and not reopened here — and the
  rotation goes further: its key is not trust material at any number of sightings until an
  operator says so.
- **Derive services for the contested group.** The dropped half of step 1, above.
- **MAC or hostname as the discriminator.** Neither is in the evidence (B43): discovery emits no MAC
  and no engine emits a hostname. When they land they join the continuity facts as further
  narrowing — MAC is weak by ADR-007 and would verify nothing either.
- **Leave it to B39's operator screen.** The screen is still needed (an item that fails the
  classification still waits there), but making the common case an operator task is how the queue
  becomes a place nobody looks.

## Consequences

- A host that rotates its key and keeps its services rejoins the inventory on the second scan after
  the rotation, with a full audit trail. Its credentialed scans refuse until an operator pins or
  confirms the new key: a key change on a credentialed host is a human decision, by design. **No
  such verb exists yet**: `known_hosts` on a credential profile has a reader and no writer in the
  API or the CLI, and nothing resolves a queue item, so today `rotation` and `lapsed` are permanent
  and the Health chip warns with nothing behind it. That is B39, next in order, and it is why B39
  is not optional.
- The OS fact is lenient by design: an asset with no attributed family imposes nothing, which is
  most of a non-Linux estate, so the "four facts" are three there and two against an adversary who
  holds the SSH port. Stated beside the other leniencies.
- A host whose rotation coincides with a service change (a reimage that also moved from nginx to
  Apache) waits for an operator. That is the threshold working as stated, and the ADR says which
  fact failed in the `identity.contested` reason.
- An estate with DHCP churn still accumulates parked hosts for B39: a genuinely different host on a
  reused lease fails service continuity by construction, unless it happens to run the same products
  on the same ports with the same OS — and then it attaches, per the paragraph above.
- `services` rows that stopped being seen inside the window make a host's rotation unclassifiable
  until they age out of the window or an operator resolves it. Stated so it is not read as a bug.
- A **dual-homed** host can never classify: `services` is keyed by asset, not by address, so a port
  only ever answered at the host's other address is "held" and never observed at this one, and it
  never ages out while the other address keeps it fresh. Such a host waits for an operator (B39).
  The fix is an address on the service row, which is B43's neighbourhood, not this ADR's.

## What this does not discharge

- **B44 (new): the SSH fingerprint probe verifies no possession.** The SSH engine reads the host-key
  blob out of the key-exchange reply, hashes it and abandons the exchange; the signature in the same
  message is never checked, so an SSH host key is an echo anyone can present after one
  `ssh-keyscan`. The TLS probe is **not** in that state: Go's handshake verifies the server's
  signature over the transcript even with chain verification disabled (the review measured an
  echoing server refused with a signature failure), so a certificate fingerprint costs the victim's
  private key. The echo attacks the reviews measured rest on the SSH half; it is why a contested
  address parks even the occupant's own agreeing sighting. Completing the SSH key-exchange signature
  check in the fingerprint engine would turn an observed host key from an echo into a proof and is
  the real fix — an engine change, not this ADR's.
- The `identity.contested` event for a park that names no candidate is keyed to the address with no
  resource id, which the asset-timeline read cannot return; the address survives in the detail. B39's
  queue screen reads the items themselves.
- A `rotated` item pins its asset row: the CHECK requires `resolved_asset_id`, and the FK is
  `ON DELETE SET NULL`, so the asset cannot be deleted while the item exists — the same shape as
  `merged` (0013), reachable now. B39's delete/merge verbs must close or re-point items first.

- B39 (the queue's operator surface, window-as-policy, sightings-needed on the asset page, clear a
  pin), B40 (ungraded merge evidence), B42 (same-service is first-seen port), B43 (MAC and hostname
  absent from the evidence), B35, B36, B38.
- A group whose write the store refuses (a constraint no caller anticipated) is logged and retried
  every sweep with no item and no signal, and holds its slot at the head of the batch — the shape
  the canonicalisation and the protocol grammar now prevent for the two causes measured, but not in
  general. A park-on-store-refusal path belongs with B39's queue work.
- The rule does not run over a parked group that is never observed again: a host that rotated and
  then went quiet stays in the queue for B39. Nothing re-examines a pending item without a new
  sighting, deliberately — the classification needs a second scan, and inventing one is the thing
  it must not do.
