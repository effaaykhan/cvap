# ADR-055: The enrollment-token prefix, and its now-half-moot secret-scanning rationale

**Status:** Accepted
**Date:** 2026-09-05

## Context

Enrollment tokens carry a `cvapent_` prefix (`internal/control/enrollment/token.go`,
`TokenPrefix`). The decision was made in the session-7 planning exchange and landed as a code
comment, never as an ADR. Three rationales were given for the prefix at the time, and one of the
three no longer holds now that the repository is private — so this records the decision and
amends it, rather than restating it. It is an **amendment, not a reversal**: the prefix stays.

## Decision

Enrollment tokens keep the `cvapent_` prefix. The three original rationales, with their status
now stated explicitly:

- **Greppable in logs and ticket systems.** Still holds. A fixed, distinctive prefix means an
  operator or an incident responder can search for a leaked or mishandled token by string.
- **Identifiable on sight** when pasted into a ticket, a chat, or a config file. Still holds,
  and it lets a scan point reject an obviously-wrong paste before spending a round trip.
- **Matchable by GitHub secret scanning.** Does **not** currently hold. GitHub secret scanning
  on a *private* repository requires GitHub Advanced Security, which this repository does not
  have. On a public repo the platform scans by default; on this one, that control is simply off.

So two of the three justifications are intact and one is inoperative. The prefix earns its keep
on the two that remain, which is why this is an amendment and not a removal.

### What would re-enable the scanning rationale

Named concretely, because "it's off" without the condition to turn it on is how a dormant
control gets forgotten:

- **Enabling GitHub Advanced Security** on the repository, or
- **the repository returning to public**, where secret scanning runs by default.

Either restores platform scanning of commits for the prefix. **But neither is sufficient on its
own**: registration with GitHub's secret-scanning **partner programme** — telling the platform
what the `cvapent_` pattern *is* and where to report a match — was noted as deferred when the
prefix was chosen and remains outstanding. A scanner that has not been told the pattern gets
little from it. So the re-enable path is "one of the two conditions above **and** the partner
registration", not either condition alone.

## Alternatives considered

**Drop the prefix, since a third of its case is gone.** Rejected: two of the three rationales
are unaffected by repo visibility, and greppability alone justifies it. Removing it would also
be a wire/format change to a token scan points already parse.

**Leave the code comment as the only record.** Rejected, and it is the specific thing this ADR
fixes. The comment stated the secret-scanning rationale without qualification — a comment
claiming a control that is not currently active, which is a pattern this repo has caught five or
six times (a documented capability read as present when it is not). The comment is now pointed
at this ADR rather than restating the three rationales, so the two cannot drift and the "off"
status has one home.

## Consequences

A leaked token committed to this repository **will not be caught by GitHub** today. The
compensating controls that do exist bound the leak; none prevents it:

- **Short TTL.** `DefaultTTL` is 24h, `MaxTTL` 7 days (also a CHECK constraint in migration
  0017). A leaked token is useful only until it expires.
- **Single use.** The first successful enrollment consumes the token under a row lock
  (`store.EnrollmentTokens.Redeem`). A token the legitimate scan point has already used is inert
  to a later thief; a token a thief uses first is then inert to the operator, whose enrollment
  fails — turning a silent theft into a visible one.

One correction to how the audit trail was described when this ADR was drafted, because it is the
very pattern above: there is **no audit event on the *replay* of an already-used token.** A
replayed or otherwise-invalid token is refused with the single uniform `errEnrollmentRefused`
(so the refusal is not a token-existence oracle) and logged to **Core's own logs**, but the
enrollment transaction rolls back before any audit write, so no `audit_events` row is recorded
for the refusal. What *is* recorded is a **successful** enrollment — `scan_point.enroll`, naming
the `token_id`, zone and certificate fingerprint — and that is the real detection surface for a
leaked-but-unused token: a rogue scan point enrolling on it leaves an audit event, which single
use then prevents the legitimate scan point from ever completing. The compensating controls are
therefore the TTL, single use, and the audit of *successful* enrollment — not an audit of the
refused replay, which does not exist.

## Review trigger

Enabling GitHub Advanced Security, or the repository returning to public — either of which makes
the scanning rationale live again and forces the deferred partner-programme registration back
onto the table. Also the first design partner (see ADR-054): a third party with repo access
widens who could read a committed token, which sharpens the value of the platform control being
off.
