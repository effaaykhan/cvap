# ADR-094: A key CVAP observed is trust material at an address only after two scans there; an address handover is queued, not attached

**Status:** Accepted
**Date:** 2026-09-11
**Follows:** ADR-093 (frozen), whose decision 1 recorded moderate keys on an attach and whose review
measured what that widened. Amends ADR-093 §1's recording rule and the attach branch of the resolver
(a shape ADR-007 never described — ADR-007's queue-on-conflict and "one moderate key alone does not
merge" are untouched), and ADR-091 §4's observed-trust source for one provenance (attach) and one
scope (the dialled port).

## The problem, stated by the review and accepted here

ADR-093 made the correlator record a host's moderate keys on an attach so an asset discovered before
it was fingerprinted could ever gain a key, which ADR-091's observed-trust path needs. The security
review measured the cost: the observed trust root for an address became **the first key anyone
presented there**, and an attach happens on any address handover. Before, first sight was an
enrolment moment — a merge or a new asset. After, it was ambient, and its failure silent: a
credential goes to whoever answered.

Trust-on-first-use is defensible when first sight is deliberate. It was the right mode for a
controlled run over three owned hosts with a discovery pass the operator ordered. It is the wrong
resting state.

## Decisions

1. **Provenance on every identity key** (migration 0044): `merge`, `new_asset`, `attach`, and
   `unknown` for rows that predate the column. `Record` takes it from the verdict and never
   changes it. It is the audit record of how a key came to be held; it does **not** decide trust.
   The first draft of this ADR let an enrolment-grade key (`merge`/`new_asset`) count on one
   sighting at the address it was recorded at. The security re-measurement showed that a "new
   asset" is not an enrolment moment either: address intervals age out after seven days, and a
   newcomer answering at a quiet address is then a new asset, trusted at once — first sight on a
   timer. So there is no exemption.
2. **Trust is two distinct scans at the address, counted per key and per address.**
   `asset_identity_key_sightings` holds one row per (key, address, port) with `scans_seen`,
   `last_seen_scan` and `last_seen_at`; `Record` counts a sighting only when the recording scan
   (resolved from the observation's task) differs from the last one that saw the key there, and is
   later. The occasion is the scan, never a timestamp: the review inflated a timestamp-based count
   from one scan three ways (two address groups in one sweep, the 500-row batch cut, a merge
   re-recording its own evidence). Any verdict counts, a merge included: what keeps a merge from
   promoting the keys that justified it is that its sighting counts once, at its own address. A
   scalar count on the key row was tried and starved dual-homed hosts (trusted at one address at
   best, at neither when scan order alternated); the child table counts each address on its own.
   `asset_identity_key_sightings` is the nineteenth table the v2 ERD does not draw (ADR-029's
   list, recorded here as the later ones were in their own ADRs; B27 remains the redraw).
   `SSHHostKeyFingerprintsAt` — what ADR-091's `known_hosts` is composed from in observed mode —
   returns a key for an address when it is live on the asset at that address and has two sightings
   **at that address, on the port the engine dials** (`sshalgo.DefaultPort`, one constant for the
   engine and the query, as `HostKeyPreference` is), **inside the address window**. The port is part
   of the sighting's key, not read from the copied evidence payload: a key row copies the
   observation that first recorded it, so the payload's port is where the key was first seen, and
   the review measured a host serving one key on 2222 and 22 refused on 22 forever. A sighting
   ages with the address relationship it rests on (`store.SightingWindow` equals
   `correlate.AddressWindow`, seven days, asserted by a test): the review measured an attacker who
   paid the two-scan cost, left for months, and was trusted again on one scan because a count
   that never decays makes the cost a one-time payment — and measured it again when the first fix
   only required the *latest* sighting to be recent ("at least two ever, and one recently" is
   satisfied by one returning scan). The count now restarts at 1 when a sighting arrives more than
   the window after the previous one; the store test performs the return. The window is also a
   scheduling constraint, stated here: a credentialed job needs an SSH *fingerprint* observation
   at the address within seven days, not merely a live address — a discovery-only scan refreshes
   the address and not the sighting — so a host parked (B41) or unfingerprinted for a week loses
   credentialed coverage until fingerprinted twice again. And because the count restarts after a
   gap longer than the window, **an estate fingerprinted less often than every seven days can
   never build observed trust at all**: every sighting is a restart. That is the operator's
   schedule to set, or the pin's job. Fails closed. The port scope is what makes the
   same-service handover rule (§4) sufficient: a key presented on 2222 contradicts nothing held
   from 22, attaches, and is counted for 2222 — and is trust material for port 22 never. One latent seam, stated so it is not discovered later:
   the engine's `Port` is never set by a job today; the day an assignment names a port, Core must
   compose `known_hosts` for that port or the verification fails closed and "one constant" stops
   being true silently. Keys from before this ADR have no sightings and are trusted nowhere until
   two post-migration scans see them at an address — a pre-existing key needs **two** more
   fingerprint sweeps, and a credentialed job in between is refused ("trust-on-first-use is not
   permitted"). The three Phase 4 hosts pay it; a backfill from `asset_addresses` would re-create
   exactly the one-sighting trust this ADR refuses.
3. **Two sightings are a narrower window, not a verification.** Say it plainly: requiring a second
   scan at the address makes the attack need persistence there across scans rather than timing one,
   and an attacker who holds an address for two scans is trusted exactly as a legitimate host is. Nothing here
   authenticates a key. The real answer remains the operator pin (ADR-091 §4, `operator` lines win
   outright), and this is the honest default for fleets too large to pin.
4. **An address handover is queued, not attached** (`domain.Resolve`, B37 closed) — **for SSH host
   keys**. The not-outvoted guard fired only when something *agreed*; a newcomer on a reused lease
   has nothing in common with the asset but the address and a same-service key that contradicts the
   one held, so it fell through to attach — and, after ADR-093, recorded its key on the occupant's
   asset. Now a candidate that is attachable by address and contradicted by an SSH host key is
   contested. A contradicting *certificate* is not a handover: the security re-review measured a
   web host parked forever after an ordinary renewal, and certificates renew on a schedule (ACME,
   every 60–90 days, on every TLS host) while SSH host keys do not. A renewed certificate attaches —
   the same host — and the verdict carries the contradicting key out as `Contradicted`, with what
   AGREED as `Corroborated` (moderate or stronger; the address never corroborates itself).
   Corroborated — the asset's steady host key agreed **and is established**: two distinct scans at
   this address, the trust root's own bar, read before this sweep records anything, because an
   attach can write what the asset holds and the re-review planted a key on one scan and used it to
   corroborate its own certificate the next — the held certificate is retired (`valid_to`, never
   deleted) and the renewed one recorded, so the renewal survives the host's next address change.
   Said in the register decision 3 uses: an observed SSH host key is a **public value** — the
   fingerprint probe verifies no signature — so corroboration by it is an echo, not a proof; it
   raises the attacker's cost to knowing the victim's host key and holding the address across
   scans, and no more — the re-review measured a forgiven-but-unretired certificate parking
   the host at its new address forever. Uncorroborated (nothing in common with the asset but the
   address): the attach stands and **nothing is recorded**, because the re-review measured a
   different host wearing a TLS-only occupant's address — new certificate, its own sshd — riding the
   forgiven certificate in: its host key landed on the occupant's asset and two scans later was the
   occupant's trust root, with no queue item and no log line. Two consequences, stated: a host
   whose only identity is a certificate can never replace it — its renewal is indistinguishable
   from a handover, nothing else can corroborate, so the old certificate stays until a hand
   revocation (bounded: one moderate key never merges anyway); and the same newcomer who simply
   does not serve TLS contradicts nothing, records its key on scan one and is the occupant's trust
   root after scan two — the accepted two-scan cost by a route this rule does not touch. The
   uncorroborated conclusion — "the identity at this address changed" — is a WARN today, not a
   queue item (queueing it would park every TLS-only host at renewal) and not yet a health number.
   The same retire-and-replace runs on a
   MERGE at the held address (two independent keys agreeing plus a renewed certificate): the merge
   verdict carries the renewal out too, or that path would leave the held certificate live forever. The filter runs **before** ADR-007's
   not-outvoted guard, for the candidate holding this address only: the first cut put it inside the
   weak-only attach branch, and the re-review measured the common host — steady sshd, renewed
   certificate — going `agreeing=[ssh]`, `conflicts=[cert]`, contested, parked at its next renewal;
   only a TLS-only host reached the carve-out. At a different address a changed certificate stays in
   the conflict set. The filter names certificates, not "anything that is not an SSH key": a key
   type this build cannot produce yet that contradicts at the held address still reaches the guard.
   One seam, stated: "the same service" for the contradiction test is the held key's *source*,
   which `ForAsset` derives from the copied payload — the port the key was first seen on — while
   the sighting carries the port seen now; an sshd that moves port makes a genuine handover on the
   new port read as a different service, which attaches. Both branches carry their own mutation.
   In the SSH case the candidate is contested: queued for an
   operator with a reason that names the handover, the whole host group left unresolved, no key
   recorded. The whole group: the re-measurement showed a newcomer's keyless observations (a
   service on 8080 beside the contested sshd) re-grouping alone the next sweep, finding only the
   address, and attaching — the newcomer's services and findings written onto the previous
   occupant's asset through the back door — so every observation in the group now gets a queue
   item naming it and is parked with the rest. A contradiction with no address tie is unchanged (a new asset). The recording guard
   ADR-093 put in `internal/correlate` is deleted: a domain rule enforced in the caller is a rule
   the next caller does not enforce, and `internal/correlate/CLAUDE.md` says so.
5. **A queued observation waits.** The review traced what a queue verdict did before: the
   observation stayed unresolved by design, the sweep re-picked it every 30 s for 90 days,
   `Enqueue` had no dedup (migration 0013 built the index for a check nobody wrote), and — worse —
   the parked newcomer was grouped with every later observation at its address, so the occupant's
   own next sighting was contested too: one handover froze the address. Now `ListUnresolved` skips
   an observation that has a pending queue item, `Enqueue` writes one item per (observation, key),
   and the correlate test sweeps twice more and observes the occupant again to prove neither
   happens. The parked observations return to the sweep when the item is resolved — and nothing
   can resolve one yet: **B39**, the queue has no operator surface. A sighting's time is the host
   group's newest `observed_at` (`h.seenAt`), not the sweep clock, so the count is a function of
   what was observed and a re-run correlation does not graduate keys by itself; a `Record` with
   no scan id, no address or no port never counts as a sighting.

Measured, through `make store-test DB_TEST_PKGS="./internal/store/... ./internal/correlate/...
./internal/dispatch/..."` (a bare `go test` skips every one of these — §5.14), `make rls-test`,
`make mutate` and `make lint`: `TestAnObservedKeyIsTrustMaterialOnlyAfterTwoScansAtTheAddress` (nothing
after one sighting of a new-asset key; nothing after a same-scan re-record; trusted after a second
scan; a second address counted on its own while the first keeps its two; occasion-less records
count nothing; a port-2222 key counted and trusted for 22 never), `TestAnAddressHandoverIsQueuedNotAttached`
(domain, with its own mutation, plus the renewed-certificate, steady-key-and-renewal, merge-with-renewal
and different-address cases), the correlate handover step (a queue item per observation in the
group, all of them unresolved, no new key, no service from the keyless sibling, and no growth or
contest across two further sweeps), `TestAnUncorroboratedContradictionRecordsNoKey`,
`TestACorroboratedRenewalRetiresTheOldCertificate` and `TestAPlantedKeyCannotCorroborateItsPlantersCertificate`
(each on distinct scans, since the occasion is the scan), and the credgrant refusals "key seen once at
the target" and "two host keys qualify at the target". The ADR-007 control
(`TestOneModerateKeyAloneDoesNotMergeAcrossAnAddressChange`) and the not-outvoted mutation anchor
are untouched.

## The Phase 4 headline, restated

ADR-087 reported credentialed false positives at 0% on `.138`, `.146` and `.148`. ADR-093 measured
the production route and found 551 kernel findings on `.146`, a host running a kernel at the fix:
the engine reports binaries under their source package, an old ABI's packages stay installed beside
the new kernel, and the matcher cannot see which one runs (B36). That is the single largest error
source measured in this phase, from one missing read on an engine that already makes two.

The headline is therefore: **credentialed FP is 0% on the measured set with the kernel class
excluded and named.** "0%" is true for packages whose installed version is unambiguous; the kernel
is the counterexample, and any host that has rebooted into a newer kernel while the old ABI's
packages remain carries one false finding per CVE in every USN between them. B36 is positioned
ahead of anything that consumes credentialed findings — the console's credentialed numbers, any
accuracy claim, any customer-facing figure — and until it lands those surfaces must say so or
exclude `linux`.

## What this does not discharge

- B36 (the kernel read), B35 (the credentialed engine outside the rate and fragile model), B38
  (progress after terminal).
- The resolution queue is where handovers now land and wait, and nothing can resolve an item: B39.
  An estate with DHCP churn accumulates parked hosts until that screen exists.
- The handover rule is same-service by construction; the port-scoped trust root is what makes that
  acceptable. A key planted on another port is inventory on the asset and trust material for
  nothing.
- **The planted-keys merge is open, and this ADR says so.** Sightings gate the trust root, not
  the merge rule: `ForAsset` and `LiveByValue` return a once-seen key as full ADR-007 merge
  evidence. An attacker who answers SSH and TLS at a victim's address for one scan
  plants two moderate keys on the victim's asset; presenting the same two at their own address
  then merges their host onto it — one asset holding both addresses, findings and exposure
  interleaved. Measured by the review. What this ADR closes is the credential consequence: with
  trust counted per address, the attacker's key is the victim's trust root only after two distinct
  scans have seen it *at the victim's address*, whichever order the attacker enrols and spoofs in
  and wherever else the key is seen. Gating merge evidence the way the trust root is gated is a
  change to ADR-007's rule and needs its own decision: **B40**.
- **A host that rotates its SSH key is parked, and stays parked.** The handover rule cannot tell
  "a different host on a reused lease" from "the same host after a reimage or `ssh-keygen -A`",
  and the second is the common case. Measured by the security re-review: a host fingerprinted at
  OpenSSH 8.9p1 that rotates its key and is scanned three more times keeps its 8.9p1 service row
  forever — every later sighting is queued, then parked, and nothing derives a service or a
  finding from a parked observation. Before this ADR the same host attached and its inventory
  kept updating (the key was simply not recorded). This is a detection-evasion primitive under
  the target's control (rotate once, disappear), and with B39 open it is indistinguishable from
  a silent drop — `ResolutionQueue.PendingCount` has no reader at all; the only signals are the
  per-enqueue WARN and Health's unresolved-observation count, which deliberately does NOT exclude
  parked observations (`CountUnresolved` has no queue anti-join, unlike `ListUnresolved`): a parked
  observation is still uncorrelated and must stay counted, and that count is the one number that
  moves when a host rotates its key. It is not fixed here because
  the two remedies are both domain decisions: derive services for a contested observation while
  withholding identity, or auto-resolve as rotation when the new key is seen on N distinct scans
  and the old one on none. **B41**, and it is put to the operator ahead of any estate where hosts
  are reimaged.
- A key revoked by hand (`valid_to` set; the only Go path that closes a key is the corroborated-renewal retire) is re-created at one sighting by the
  next scan that sees it. Adjudication and revocation both wait on B39's surface.
- **After a successful two-scan spoof, it is the real host's return that gets parked.** The
  handover rule protects whoever holds the record; once an attacker has paid the accepted cost and
  is the key-holder at the address, the victim answering with its own key is the contradiction,
  and every one of its sightings is queued until B39 adjudicates. The victim is removed from the
  inventory rather than restored. Measured by the re-review; the converse holds (a victim that
  already holds its key is not displaced by any number of attacker scans).
- **Two distinct host keys qualifying at one address and port is refused.** `trustMaterial` no
  longer composes two `known_hosts` lines — whichever machine answered would have been accepted.
  The re-review reached that state through the first-seen-port seam above (a host stamped `2222`
  by its first sighting, a newcomer on 22 contradicting nothing); the refusal fails closed until
  the resolver compares keys per sighting rather than per key row: **B42**.
- **A different TLS host on a reused lease reads as a renewal.** The certificate carve-out cannot
  tell a renewed certificate from a different host's certificate: a newcomer presenting a new
  certificate on 443 and, say, MySQL on 3306 attaches to the previous occupant, its services land
  there, and its own certificate is dropped as `Contradicted`. Pre-existing (ADR-093 behaved the
  same) and no credential consequence — certificates are not trust material — but inventory
  damage, and it belongs beside B37: the queue is for SSH host keys only. Its sharper form — the
  newcomer also brings an sshd — now records nothing (uncorroborated), so it reaches no trust root.
- **An SSH-only host that changes address is a new asset that holds no key** (ADR-007: one
  moderate key alone does not merge; the key stays live on the orphan, and nothing in Go ever
  closes a key), so it cannot be credentialed at the new address at all — not after the old
  interval ages out, not ever — short of an operator pin or a hand revocation of the orphan's
  key. Pre-existing, not a regression; stated because `internal/correlate/CLAUDE.md` names SSH-only Linux as the common
  estate and "two more sweeps" is not the cost there after a move.
