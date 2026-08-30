# ADR-028: One pre-release correction to the frozen wire contract

**Status:** Accepted
**Date:** 2026-08-30

## Context

`proto/` was frozen at bd0e4f9 and ADR-022 makes it additive-only within a major version:
no removals, no renumbering, no semantic change. `buf breaking` enforces that with the FILE
category against a moving baseline — the previous commit locally, the merge base in CI.

A security sweep of the contract found `RotateRequest.current_fingerprint`. It was documented
as defence in depth: Core compares it against the TLS peer certificate and refuses a
mismatch. It cannot be that. A certificate fingerprint is a digest of the public half — Core
returns it at enrolment in `EnrollResponse.cert_fingerprint`, it appears in audit records,
and any peer that completes a handshake with a scan point can compute it. It is a non-secret,
attacker-known value sitting in a field shaped like an authentication input, next to
`scan_point_id`.

The shape is the defect. It invites the implementation that checks the body instead of the
peer certificate. That check reads as authentication, passes every test written against a
well-behaved client, and turns `RotateCertificate` into a re-key oracle: any enrolled scan
point could name another's id and fingerprint and be issued a certificate for that identity.
Being documented as a control made it worse, because a field described as a control gets
relied on as one.

ADR-022 permits removal only at a major version bump. But v1 has never been released. No scan
point exists, no customer runs a build, and the frozen baseline is one commit old. The fleet
whose existence is ADR-022's entire argument is not there to be broken.

## Decision

Correct the frozen baseline once, before first release: delete field 3 from `RotateRequest`
and reserve both its number and its name. `gen/` is regenerated, so the Go field
`CurrentFingerprint` is gone. The reservation comment states the mechanism, so the next
reader learns why the field is absent rather than proposing it again.

**ADR-022 is not amended and not superseded.** What this records is the boundary condition it
left implicit: the additive-only rule binds from the first release of a scan point build.
Before that there is no version skew to protect, because there is no deployed build. After
this commit the contract is frozen again, on the corrected baseline, on exactly ADR-022's
terms.

Nothing is suppressed in `buf.yaml`. `buf breaking` reports `FIELD_NO_DELETE` for the single
commit that lands this, against the pre-correction baseline, and that report is correct — the
change is a deletion. A `breaking.ignore_only` entry for `enrollment.proto` would silence it,
but a suppression outlives the commit that needed it and would then permit the deletion of
`enrollment_token` or `csr` in silence. That is the gate-that-silently-passes failure this
repository is built to avoid. Because the baseline is a moving ref, the gate is clean from
the next commit onward without any configuration change, and this ADR is the record that the
one failure was deliberate rather than missed.

## Alternatives considered

**Keep the field and correct its comment.** The additive fix, and the form ADR-022 normally
forces. Rejected: the defect is the field's shape, not its documentation. A field named
`current_fingerprint` next to `scan_point_id` will be checked by someone who has not read the
comment above it, and under ADR-022 it would be there for the life of the major version. A
comment is read once; a field is available forever.

**Bump to v2.** ADR-022's stated mechanism for a removal. Rejected: a major version exists to
give a deployed fleet a migration path. There is no fleet. It would be bookkeeping that also
teaches the wrong lesson — that the freeze is negotiable by ceremony rather than by argument.

**Suppress `FIELD_NO_DELETE` for `enrollment.proto` in `buf.yaml`.** Rejected above: it turns
one deliberate exception into a permanent hole in the file that holds the enrollment token
and the CSR.

**Leave the freeze date implicit and treat this as an unrecorded exception.** Rejected: an
undocumented exception to the repository's strictest rule is how the rule stops being one.

## Consequences

The additive-only rule now has a stated start, which it did not have before. That is a
tightening, not a loosening: it names the moment after which no correction of this kind is
available.

A second pre-release correction would need its own ADR, and should be read as evidence that
the contract was frozen before it was ready rather than as a precedent. The freeze exists to
make that cost visible, and it did — this defect was found because the contract was reviewed
as a contract.

One commit in the history fails `make proto-breaking` when compared against its predecessor.
Anyone bisecting the gate across that commit needs this ADR to tell the deliberate failure
from a real one.

## Review trigger

The first release of a scan point build. From that point removals require a major version
under ADR-022, with no pre-release exception available.
