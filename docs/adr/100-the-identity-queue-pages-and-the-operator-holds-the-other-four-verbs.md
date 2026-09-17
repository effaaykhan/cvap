# ADR-100: The identity queue pages, a refusal is recorded, and the operator holds the other four verbs — B39's second slice

**Status:** Accepted
**Date:** 2026-09-15
**Follows:** ADR-097 (the first slice: confirm, the two adjudication verbs, the Identity screen), ADR-091 §4
(the operator pin outranks the observed key; `known_hosts` had a reader only), ADR-094/096 (two windows,
two constants, asserted equal), ADR-095 (a pinned exact attribution had no operator path to clear).
**Closes:** B39's second slice, as ADR-097's last section listed it: `identity.refused`; paging on the
queue listing; the sighting window as a setting tied to scan cadence; a pin writer on credential profiles
in the API and CLI, and clearing a pin; the asset-timeline read of audit events; clearing a pinned exact
attribution.

## What was measured

Two performance claims sat in the backlog; both were measured before anything was designed, with a
throwaway probe seeding the dev database (200 addresses × 200 items with distinct keys, plus one address
carrying 3 000 items):

| measurement | result |
|---|---|
| `GET /v1/identity/queue`, a page at every cap (200 addresses, 50 items and 200 keys each) | **9.6 MB, ~540 ms**, three runs within 25 ms |
| one address, `?address=` | 43 KB, 40 ms |
| `discard` over 3 000 items at one address | 75 ms |
| `same_host` over 3 000 items, one key | 136 ms |

The listing was the cost: one screen pulling nearly ten megabytes. The "936 ms `pendingAt` inside the
write transaction" figure did not reproduce at 3 000 items on this box (the whole verb was 75–136 ms);
the verbs read the whole address on purpose (ADR-097: a decision is computed over the whole question),
and that stays.

## Decision

**1. The listing pages by keyset.** `?limit=` (default 25, at most 200) and a cursor of the listing's own
order, `(last_seen, address)`, sent back as `?before=` and `?before_address=`; the response carries
`next_before`/`next_before_address` while there is more, and `addresses_total` on every page so a client
knows what it has not seen. Half a cursor is refused. `?address=` still returns one group and never a
cursor. The Identity screen loads 25 and walks the cursor with "show more"; a decision resets the pages.
`TestTheQueuePagesByLastSeenAndAddress` — including the tie case, because the ADR-compliance review
measured the first cut's whole-tuple `<` re-serving page one on tied `last_seen` and leaving the tail
reachable only by `?address=`, and ties are the normal case: one sweep parks every address it contests
at one instant. The tie-break follows the listing's own order (older first, then greater address), and
the cursor is offered only when a next group exists (the listing fetches one past the page).

**2. A refused verb is recorded.** `identity.refused` — the verb, a refusal code (`nothing_pending`,
`ambiguous_group`, `key_not_parked`, `nothing_to_record`, `too_many_keys`, `keys_changed`), and what was
asked — written in its own transaction from the captured error, because the decision's transaction
rolled back with the refusal. A validation error (400) is not a refusal and records nothing; a store
failure is logged as the failure it is. The record is keyed to the asset **holding the address**, never
to the asset id the caller named (which need not exist — the review noted a prober choosing where the
mark lands, or that it lands nowhere) and never to nothing for `different_host`/`discard`; the caller's
asset id is in the detail. `TestARefusedVerbIsAudited`.

**3. The sighting window is a tenant setting, tied to the scan cadence it must accommodate.** Migration
0047 adds `identity_settings` (one row per tenant, RLS, `sighting_window` bounded 1–90 days; absent row =
7 days). `store.IdentitySettings.Window` is read *inside each transaction that uses it*: the sighting
decay in `AssetIdentityKeys.Record`, `EstablishedAt` and `SSHHostKeyFingerprintsAt` through their
callers, the correlator's ageing pass, `domain.Resolve`, `ContestFresh` and `continuityFor`, the
dispatch producer's trust composition, and the asset page's trust chips. `store.SightingWindow` and
`correlate.AddressWindow` — two constants asserted equal by a test because their packages must not
import each other's reasoning — are gone; the test that asserted their equality now proves the store's
decay reads the tenant's setting (a 48-hour window, two sightings three days apart, the count starts
over). `GET/PUT /v1/settings/identity` shows the window beside its bounds and the **measured** cadence —
the median gap between the tenant's last ten completed scans — and refuses a window under twice that
cadence with the number in the message: two scans must land inside one window for an observed key to
become trust material (ADR-094), so a shorter window would turn the credentialed path off without
anyone noticing. `identity.window_changed` records from/to hours, the reason, and the cadence measured
at the time. `TestTheSightingWindowIsATenantSettingTiedToScanCadence`.

Three things the cadence rule does not do, stated so they are decisions rather than gaps. With fewer
than two completed scans the cadence is unmeasurable and any window inside the bounds is accepted — a
fresh deployment sets its window before it has scanned, and refusing everything until it has would be a
rule with no measurement behind it; the Settings card says the cadence is unmeasured. The rule is
checked at the write and shown on the card beside the current value: the card compares the window to
twice the measured cadence whenever it renders, so a tenant on the default that scans every five days
sees the warning without editing anything; nothing re-evaluates it on Health yet. The sample is
tenant-wide across policies and scan types, which is the cost of a tenant-level window (below).

**Why a tenant setting and not a scan-policy field.** ADR-097 and B39 wrote "policy setting". The window
governs correlation, ageing and the trust root — properties of the tenant's address space, not of a
scan: one address answers to one window, and a per-policy window would put two windows on the same
address the moment two policies scan it. The write is gated on `policy.write` because it is the closest
existing authority for tuning what scans mean; the value is stored per tenant.

**4. The operator pin has a writer, in the API and the CLI.** `hostkeytrust.ValidatePin` is the one
validator both use: plain `host[,host] keytype base64` lines that x/crypto's parser accepts, no
`@` markers, no hashed hosts (a hashed host matches no target by name, so it pins nothing an engine can
use), at most 64 KiB and 1 000 lines, at least one line — an empty pin is a TOFU shape, and clearing is
its own verb. `GET /v1/credential-profiles` lists the non-secret face of each profile (never the secret
or its pointer, asserted by test); `PUT /v1/credential-profiles/{id}/known-hosts` pins, `DELETE` clears;
`cvap-cli credential pin --known-hosts FILE` and `credential unpin` do the same at a shell, audited with
`via: cvap-cli`. A new permission, `credential.pin`, holds the authority apart from `policy.write` the way
`identity.resolve` is held apart from `asset.read`: a pin re-roots credentialed trust by hand.
`credential.pinned` records the SHA256 fingerprints of every pinned key (public material);
`credential.pin_cleared` records how many lines went. The Settings screen carries both.
A host pattern (`*`, `?`) or a negation (`!host`) is refused for the same reason as a hashed host:
`LinesCovering` matches a target by exact name, so such a line pins nothing an engine can use and every
job for the host it meant to cover would refuse. Permissions the slice relies on: `policy.read` lists the
profiles, `credential.pin` writes them; a deployment bootstrapped before this permission existed has it
in no role until roles can be edited (ADR-097's precedent), and `cvap-cli credential pin` is the path
there, which the runbook says. `TestAnOperatorCanPinAndClearHostKeysOnAProfile`,
`TestCredentialPinAndUnpinWriteTheProfileAndAudit`, `TestValidatePinAcceptsPlainLinesOnly`.

**5. The asset has a timeline.** `GET /v1/assets/{id}/events` — `AuditEvents.ListByResource`, which had no
production caller — lists every event keyed to the asset, newest first: contests, rotations, expiries,
decisions, refusals, cleared attributions. The asset page renders it. `TestTheAssetTimelineListsWhatHappenedToIt`.

**6. A pinned exact attribution can be cleared.** `POST /v1/assets/{id}/attribution/clear` re-stamps an
exact `os_provenance` (source `os-release`) and/or `release_provenance` (source `package_manager`) as
`operator_cleared`, keeping the previous provenance under `was` and the values in place, so the next
inferred sweep may land where the exact rank would otherwise hold for ever (ADR-095's "clear a pin and
re-derive"). Refused (409) when nothing exact is held. `asset.attribution_cleared` names what was
cleared. The asset page shows the verb beside an exact attribution. The authority is `identity.resolve`:
it is the same operator's-word-over-host-derived-truth decision the confirm verb makes, and the review
is right that it widens what that permission does — it now also lifts an attribution that drives
advisory matching; a deployment that wants the two apart splits the permission then, and this ADR
names the widening rather than leaving it implicit. `TestClearingAPinnedAttributionLetsInferenceLandAgain`.

**What is deliberately not changed.** The verbs still read the whole address (measured fine at 3 000
items). Nothing here verifies a host key: a pin is an operator's word, and the screens say so beside
the buttons (B44). Credential profiles are still created at provisioning, not through the API — this
slice pins keys on one, it does not create one.

**What the security review measured, and what changed.** A refused `confirm` copied its `keys` array
into the audit detail — ~1 MiB per refusal at 400 a second from one operator, and a 481 MiB timeline page
at the 500-event cap. The refusal records a bounded view (20 names, 128 bytes each, and the count), and
`AuditEvents.Record` now caps every detail at 16 KiB with a truncation marker, so no later caller can
repeat it. `ClearExactAttribution`'s `RETURNING` was NULL on a plain asset (a NULL provenance column
poisons the boolean), a 500 where the ADR specified 409; `coalesce(…, false)`, and a case on an
unattributed asset. `sighting_window_hours` was multiplied into a `Duration` before its bound, so the
largest number an operator could type wrapped to the shortest window; the integer is bounded first. A
pin line with a control character reached the text column as a 500, and one for `[host]:2222` was
accepted and covered nothing; both are refused by name. The dispatch producer reads the window once per
job. Not changed, and stated: `asset.read` is the bar for the asset timeline, which carries adjudication
details verbatim (reasons, actor ids) — no credential material, but the lowest read bar in the system,
and an `audit.read` permission is the fix if a deployment wants them apart; `identity.window_changed`,
`credential.pinned`/`pin_cleared`, and a refusal at an address nothing holds have no API reader yet
(they are keyed to the tenant, the profile, or nothing), so "every refusal on the timeline" holds
where an asset holds the address; a refusal's audit write follows the request context, so a client
that hangs up during a slow refusal can lose the row (measured only as the handler never running).

## Consequences

- An operator can now do everything ADR-097 left to SQL: see what happened to a host, lift an exact
  attribution, pin or clear a trust root, tune the window — each recorded with their name.
- The window has one source. A deployment that scans weekly and sets a two-day window is refused with
  its own cadence in the message rather than discovering months later that no key ever became trusted.
- The queue's cost is bounded by the page, not the queue: 25 addresses instead of 9.6 MB.
- Every refused adjudication is on the asset's timeline, so probing the verbs leaves a mark where the
  operator looks.
