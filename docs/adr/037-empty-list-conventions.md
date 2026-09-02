# ADR-037: Empty means deny for permission lists, unrestricted for constraint lists

**Status:** Accepted
**Date:** 2026-09-02

## Context

Three list-shaped fields govern what a scan may do, and all three are empty by default.
`ScanConstraints.allowed_targets` is `repeated string` on the wire, where proto3 cannot
distinguish empty from absent. `scan_policies.allowed_zones` and `scan_policies.time_windows`
are `jsonb NOT NULL DEFAULT '[]'` and are `'[]'` on every row that exists today.

Each had to be given a reading before it could be enforced, and the readings are not the same.
Taking the deny-all reading for `allowed_zones` or `time_windows` would stop the fleet on the
migration that enforced them, because every existing policy would become a policy that permits
no zone and no hour. Taking the unrestricted reading for `allowed_targets` would mean a scan
point that receives no allowlist scans anything, which is the fail-open direction ADR-024
control 1 exists to close.

## Decision

Empty means **deny all** for a list that enumerates permission, and **unrestricted** for a
list that enumerates constraint.

- `allowed_targets` — **empty denies everything.** It answers *where may this scan reach*, and
  the safe answer to an unset question is nowhere. Empty and absent are indistinguishable in
  proto3, so they mean the same thing. Both enforcement sites read it identically: Core refuses
  the job when it is claimed, with an audit event, and a runtime that receives no allowed
  targets MUST send nothing and fail the task. (ADR-024 calls Core's side "planning"; the check
  runs at claim time in `offerWork`, which is the last moment before a target leaves Core.)
- `allowed_zones`, `time_windows` — **empty is unrestricted.** They answer *is this scan
  restricted*, and an unset restriction is no restriction. A policy with no zone list may be
  claimed from any zone; a policy with no windows may run at any hour, and
  `window_ends_unix = 0` travels to say so.

The distinction is which question the list answers, not which file it lives in. A list of
things that are allowed where nothing else is starts empty at *nothing permitted*. A list of
limits starts empty at *no limits*. Anything added later is classified by that test before it
is given a default.

This is recorded because it reads as an inconsistency to anyone who was not here: three list
fields, all defaulting to empty, two of which mean "no restriction" and one of which means
"refuse everything". The next reader who notices and normalises them would, in one direction,
open every scan's scope, and in the other, halt every fleet with an existing policy.

Content that cannot be parsed is a third case and fails closed in both families: an
unparseable window or an unexpressible scope rule fails the job with an audit event rather
than being skipped, because a restriction that silently disappears is worse than one that
never existed.

## Alternatives considered

**One convention for all three, whichever it is.** Consistency is a real property and this
gives it up. Rejected because the two candidates fail in opposite directions and neither is
safe for both families: deny-all for `time_windows` halts every existing policy on the
migration that enforces it, and unrestricted for `allowed_targets` is the fail-open reading
ADR-024 rejected outright. A convention that is uniform and wrong half the time is worse than
an asymmetry that is written down.

**A separate `restrict_zones` / `restrict_time` boolean beside each list, so empty is never
load-bearing.** Removes the ambiguity by making the intent explicit. Rejected: it creates a
state where the boolean is true and the list is empty, which has to mean deny-all anyway, and
a second field that can disagree with the first is a new failure rather than a removed one.
Two fields also do not survive proto3's empty-is-absent problem — the boolean has the same
zero value.

**Sentinel values — `["*"]` for unrestricted, `[]` for deny.** Makes both readings explicit in
the data. Rejected: a sentinel inside an authorisation list is a string that means "match
everything" sitting in a list of things to match, one typo away from being a hostname, and it
would have to be special-cased at both enforcement sites. `allowed_targets` already accepts
`0.0.0.0/0` for anyone who genuinely wants it, stated as a rule rather than smuggled in as a
magic token.

**Leave `allowed_zones` and `time_windows` unenforced, so only one convention exists.** The
status quo, and the reason this ADR was needed. Rejected: a column that governs nothing is a
control an operator believes they have. A policy naming its zones looks like a scope
restriction and was not one.

## Consequences

A policy written today with no zone list and no windows behaves exactly as it did before both
were enforced, so enforcement lands without a fleet-wide change in behaviour. A policy with no
allow rules cannot dispatch at all, and says so in the audit log rather than scanning
everything.

The asymmetry has to be restated wherever these fields are documented — it now appears in
`dispatch.proto` on both `allowed_targets` and `window_ends_unix`, and in migration 0024's
column comments — because the reader who needs it is the one who has found only one of them.
That duplication is accepted here for the same reason ADR-024's ceilings are enforced twice.

Any new list field governing scan behaviour needs its question answered before it gets a
default, and "it defaults to empty like the others" stops being an answer.

## Review trigger

A fourth list-shaped field whose question is genuinely neither — one that enumerates
permission but whose empty case cannot be deny-all without breaking deployed policies. That
would mean the two families are not exhaustive and the classification needs a third case
rather than a judgement call at each site.
