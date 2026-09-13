# ADR-097: An operator's word is the only verification — the identity queue's verbs

**Status:** Accepted
**Date:** 2026-09-12
**Follows:** ADR-007 (the unresolved queue), ADR-094 (handovers queue), ADR-096 (rotation and lapse
provenance are excluded from the credentialed trust root "until an operator confirms").
**Closes:** B39's first slice: the confirm verb, the two adjudication verbs, the queue screen, and
sightings-needed on the asset page. B39's second slice — the window as a policy setting tied to
fingerprint cadence, and clearing an operator pin — stays open; see the last section.

## What was measured

ADR-096 left a host that rotates its SSH key, or is displaced under a fresh contest, with a key the
credentialed trust root excludes "until an operator pins or confirms it". The pin (ADR-091 §4) has a
reader and no writer in the API or the CLI, and nothing resolved a queue item. So a reimage, an
`ssh-keygen -A`, or an attacker answering tcp/22 for two scans while the host's own sshd was quiet
each cost that host its credentialed coverage permanently, announced on Health with nothing behind
the chip. A live operational dead end, not a missing screen.

## Decision

Four verbs, one permission, one provenance.

1. **`identity.resolve`** is a permission of its own, held apart from `asset.read`: a decision here
   re-roots what the credentialed engine will dial with the customer's credentials, and the
   authority to give that word is not the authority to look.
2. **`POST /v1/assets/{id}/identity/confirm`** re-stamps the asset's live `rotation` and `lapsed`
   keys to **`confirmed`** (migration 0046, which adds that label and the queue's stored service
   column), which the trust root and the establishment gate exclude
   from nothing. The request **names the keys the operator is confirming**, each a live rotated or
   lapsed key on the asset, and **only those** are re-stamped: the rotated set is one an attacker
   helps compose, and the review measured the first draft — which confirmed everything rotated on the
   asset — turning one genuine rotation on 22 into a confirmation of a planted key on 2222 and a
   lapsed certificate on 443 the operator never saw, and the second draft — which required the whole
   live set to be named — leaving the operator no way to refuse a member. A key that appears between
   the render and the click is simply not named and stays where it was; a named key that is no
   longer rotated or lapsed refuses the whole request (409). The response and the audit row carry
   the keys confirmed and the rotated or lapsed keys left waiting. The key is then trust material on
   ADR-094's terms — two sightings at the address inside the window — no sooner. One
   `identity.confirmed` audit event names the operator, the keys and the reason; an asset with
   nothing to confirm answers 409, not a silent success.
3. **`POST /v1/identity/queue/resolve`** adjudicates one contested address:
   - **`same_host`** — the parked keys are the named candidate's. For each parked key of moderate
     strength or better: the asset's held key of the same service is retired and the parked key
     recorded as `confirmed`; the items close as `merged` naming the operator; the parked
     observations re-enter the sweep and attach, because the key they carry is now the one the asset
     holds. A parked key that is live on **another** asset is not moved — that is a merge of two
     assets, which is B40's question — and its item closes as `discarded` so the observation stays
     out of the sweep rather than re-parking; the response names it (`keys_held_elsewhere`).
   - **`different_host`** — the parked group is a host of its own. A new asset is created, the parked
     keys are recorded on it as `confirmed`, it takes the address (the previous holder's interval
     closes under it, ADR-008), the items close as `new_asset` naming the operator, and the parked
     observations attach to it on the next sweep. Items carrying a key another asset holds live —
     the previous occupant's own sightings, parked with the group — close as `discarded`. **It must
     record a key, or it does not happen**: a group that is only such echoes, or only address-window
     items, is refused (422) before any asset exists, because the review measured the verb creating a
     keyless asset that took the address, could never merge, and left the holder without trust at an
     address it still answered on. The right verb there is `same_host` on the holder, or discard. The
     refusal is decided after the record loop and before the address is taken, from what the loop
     actually recorded — not from a count taken first, because a pre-check is check-then-act under
     `READ COMMITTED`: a key free when it was counted was measured becoming another asset's between
     the count and the record (a correlate sweep committing the same fingerprint at another address),
     and the verb then took the address with nothing recorded. The error rolls the create back, and
     the create is the only write before that line; the refusal records nothing it then discards.
   - One `identity.resolved` audit event per decision, keyed to the asset the observations now
     belong to, carrying the address, the decision, the reason, the keys recorded and the keys
     actually retired (the retire statement's count, not the intent — under B42 a held key's
     first-seen port can differ from the parked key's and then nothing retires). The record is
     written in the same transaction as the decision: a decision whose record cannot be written is
     not made.
   - **Two keys from one service** — two hosts answered on one port (ADR-096) — is the one group
     neither verb can decide alone, and the one an attacker gets to choose; refusing it outright
     was measured as a permanent park. The operator **names which key is the host, one per
     ambiguous service** (`key_choices`, each carrying the service): the other keyed items of that
     service close as `discarded`, the decision proceeds with the rest, and the choices are in the
     audit row. The service travels with the choice because an SSH fingerprint is public and can
     be parked on two ports at once; a choice by value alone was measured binding to the first item
     carrying it, refusing the operator's correct answer and accepting only the attacker's key for
     the contested port. A service left unnamed refuses the request (422) and nothing is written —
     a single choice was measured leaving a group with two ambiguous services no exit. The listing
     names every ambiguous service over **all** parked items, not the page shown, and the service
     has one spelling: it is canonicalised **once at enqueue** from the key's Source into a stored
     column (migration 0046) that the listing, the ambiguity check and both verbs read — the review
     measured the same fact spelled four ways, and a tab in a payload's protocol splitting one
     service in two so that the screen offered no choice and every verb refused. An operator-typed
     choice is folded onto that grammar (case, whitespace) before it is compared. The **refusal is
     decided over the whole address** — every pending item there is what the operator was shown —
     and only the write is narrowed to the items naming the chosen candidate: evaluated over the
     narrowed set alone, two keys on one port whose items named different candidate sets were
     measured accepted with no choice at all, recording the attacker's key. The response and the
     audit row name the keys a choice rejected (`keys_discarded`). A decision closes exactly the items it read: a row a concurrent sweep parks
     between the read and the close is not the operator's to close, and was measured closed under
     their name unexamined. `same_host` closes only the items naming the chosen candidate; items at
     the address naming another candidate, or none, stay pending and the address stays listed.
   - The address in the request is parsed and canonicalised in the handler (`netip`, bare
     addresses only), so the audit row records the address the decision applied to, not the
     spelling the operator typed; the reason is bounded (4 KiB).
4. **`GET /v1/identity/queue`** lists the pending queue grouped by address, newest contest first,
   with the candidates, the verdict's reason (including which continuity fact failed) and the parked
   keys with a one-line summary of their copied evidence (service, product, version — the banner
   the decision turns on). Bounded in SQL: the newest two hundred addresses and the newest fifty
   items each for detail, with the full item count beside them — the review measured the unbounded
   first draft loading twenty-four thousand payloads for one page, the operator's own screen
   becoming the load an attacker's parks impose; the evidence line is truncated in SQL and the
   listing never ships a payload. **Everything a decision turns on is aggregated over every item
   at the address**, not the fifty shown: the distinct parked keys (exactly what a verb records,
   bounded by services rather than scans), the candidates (what `same_host` may name), what each
   candidate holds live on the contested services (what `same_host` retires, shown before rather
   than after), and the ambiguous services. The review measured each of these computed over the
   rendered page: a verb recording the sixty-first item's key as `confirmed` unseen, a real holder
   with no "same host" button so the destructive verb was the only one offered, a choice not
   offered for a value in the tail. A keyed item always carries its service — migration 0046's
   CHECK, and `Enqueue` refuses a keyed park without one (correlation skips and logs such a key
   rather than aborting the tenant's sweep) — because a blind item was measured passing the
   ambiguity guard and being recorded unseen. The aggregates are bounded too — two
   hundred keys per address, two hundred values per ambiguous service, with the full counts beside
   them — because "bounded by services" is a bound the attacker chooses, and twenty thousand parked
   keys at one address were measured turning the operator's screen into a 33 MB page.
   **A decision covers exactly the keys the listing shows, and nothing else.** The verbs read every
   pending item at the address once, light columns only, and decide over that whole set; an address
   with more distinct keys than a page renders is **refused** (422), because every cap that let a verb
   act beyond the page — a thousand-item window, the two-hundred-key window — was measured recording
   an unseen key as `confirmed`, and two independently capped windows were measured disagreeing with
   each other and closing the host's own keys as discarded under a choice nobody made. A verb records
   one key per distinct parked (type, service, value) and closes the items in one statement, so the
   work is bounded by what the operator saw.
   **A decision carries `seen_through`** — the listing's `last_seen`, at nanosecond precision, never
   later than now — and acts only on items parked by then: a key parked between the render and the
   click is not the operator's to decide, stays pending, and is listed again. The review measured a
   screen showing no keys at all confirming a key that landed in that window; `confirm` had been
   redesigned around exactly this and `resolve` had not. A future `seen_through` is not a set anyone
   looked at and is refused (400); so is the zero time, which parses, is not in the future, and
   would mean no bound at all (measured: a client that omitted the field acted on a key parked after
   its click). The listing is one page of the two hundred newest addresses ordered by a key the
   attacker refreshes every scan, so it carries the full contested-address count and takes
   `?address=` to reach a contest newer parks have pushed off the page; the ambiguous services per
   address are capped like the keys, with the total beside them, because their count is a port
   list the attacker chooses (measured: two hundred thousand entries, 28 MB, for one read). Every
   per-address bound is applied **per address**, never as one budget for the page — the held-key
   list had one page-wide limit spent in address-text order, and the review measured one flood
   address consuming it so a real contest rendered with no "currently held" line. And the ambiguous
   choices are computed only for groups a decision can cover: a group over the key cap can only be
   discarded, so its choices are unusable by construction, and shipping them anyway was measured at
   four hundred megabytes for one page (two hundred values, two hundred services, two hundred
   addresses — three caps whose product is not a bound). Such a group ships no choices and a total of
   zero, and the field says so; the bound that results was measured at 13 MiB for a full page of
   two hundred groups at every cap, which is the size the next slice's `?limit=` is for. The asset
   page's key list is bounded the same way — two hundred rows, one per key per address it was seen
   at — and its total counts those rows, not keys: a total of live keys beside per-sighting rows was
   measured hiding 53 of 120 keys under a warning that never fired. Keys awaiting confirmation sort
   first, so they are the last to be cut.
   - **`discard`** is the fourth verb and the exit: every pending item at the address parked by
     `seen_through` closes as `discarded` naming the operator; nothing is recorded, nothing is
     trusted, the observations stay out of the sweep. It is what an operator does with a group too
     large or too hostile to decide key by key, and the only verb the console offers for one. The console's **Identity** screen renders it with the two verbs
   and the sentence beside them that they verify nothing.
5. The asset page carries **Identity keys**: each live key, where it was sighted, on how many scans,
   and in words what the credentialed engine would make of it right now — trust material, one more
   sighting needed, or waiting for a confirmation — with the confirm verb beside a rotated or lapsed
   key. `KeySighting.TrustMaterial` is the trust root's predicate in one place — SSH, the asset
   holds the sighting's address **live**, the sighting is on the **dialled port** (22), provenance
   not rotation or lapsed, two scans, inside the window — so the sentence on the page and the
   fingerprint on the wire cannot disagree; a test drives both through a held and then a lost
   address and asserts they agree. The first draft omitted the port and the live hold, and the
   review measured the page saying "trusted" at an address the asset had just lost to a
   `different_host` decision — the failure direction in which nobody confirms or pins.

## What a decision is, and is not

None of this verifies anything. On banner data nothing can (B44): an observed SSH host key is an
echo until the fingerprint probe checks possession, and two sightings of an echo is two echoes. What
a verb records is a **decision and the person who took it** — which is the only kind of
verification an observed SSH key gets today, and the reason the audit row carries the operator's id
and reason rather than a system actor. The screen and the response say so beside every button: an
operator who confirms a key an attacker rotated in has handed that attacker the credentialed dial.

The verbs are deliberately narrow. Neither moves a key that another asset holds live; neither
changes the window or the sighting count. What they change is provenance and queue state, both
audited, both reversible by the next verb. A confirmation is asset-wide in what it re-stamps, but
what it unlocks is bounded by the address: the trust root and the establishment gate both require
the asset to hold the sighting's address live, so a key confirmed on a displaced asset — the page
says "history, not trust" — becomes trust material nowhere and corroborates nothing (the
establishment gate gained that conjunct here; it was measured re-arming at a lost address).

## Why not

- **Auto-confirm after N sightings.** That is trust on first use with a delay — ADR-094's rejected
  alternative. The whole point of `rotation`/`lapsed` is that no number of sightings of an echo
  earns trust.
- **Confirm by pinning only.** The pin is per credential profile and per host line; a rotation is
  a fact about the asset. Both remain valid: an `operator` pin still wins outright (ADR-091 §4), and
  confirming lets the observed path carry the key for fleets too large to pin.
- **A single "resolve" that guesses the decision from the evidence.** The queue exists because the
  evidence did not decide it (ADR-007). A verb that decided would be the rule the ADRs refused.

## Consequences

- A reimaged host regains credentialed coverage two sightings after an operator confirms it. An
  attacker-rotated key regains nothing unless an operator says so — and the screen says what saying
  so means.
- The queue drains by human action, the two-keys-on-one-port group included once the operator
  names the host. Growth while a contest is fresh (one item per parked key per scan, ADR-096) is
  unchanged; emptying now has a hand on the handle.
- `confirmed` keys are trust material and merge evidence like any other; the down migration of 0046
  relabels them `attach`, which is what the operator chose, and the decision survives in the audit
  log.
- Permissions are granted only in test fixtures today (ADR-043's standing note); production role
  provisioning is where `identity.resolve` gets its holders.

## What this does not discharge

- A refused adjudication (409/422) writes no audit row — correctly, since it makes no decision to
  record — so probing the verbs is visible only in the request log. A durable `identity.refused`
  through the captured-variable shape, and paging on the queue listing (today one page of two
  hundred addresses), belong with the second slice.
- **B39, second slice.** The sighting window as a policy setting tied to fingerprint cadence (today
  `store.SightingWindow` = `correlate.AddressWindow` = 7 days, asserted equal by test); clearing an
  operator pin — which first needs a pin **writer** on credential profiles in the API and CLI,
  since today `known_hosts` has a reader only; and clearing a pinned exact attribution (ADR-095). An asset-timeline read of audit events
  (`ListByResource` still has no production caller) belongs with the same slice: the
  `identity.contested`, `identity.rotated`, `identity.contest_expired`, `identity.resolved` and
  `identity.confirmed` events are keyed for it.
- B44 (possession), B40 (grading merge evidence), B42, B43, B45 — unchanged.
