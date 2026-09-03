# ADR-044: Target canonicalisation, restated with three claims corrected

**Status:** Accepted
**Date:** 2026-09-03
**Supersedes:** ADR-042

## Context

ADR-042 was committed, and then an ADR-compliance pass compared its text against the code rather
than against the index. Three of its claims were false, and one of them was false in the
direction that matters: it described a control that did not exist.

They are corrected here rather than edited into ADR-042 because ADR-042 is committed, and an
accepted ADR is superseded rather than edited. That rule is not suspended by the document being
one commit old. The alternative — "it was only committed an hour ago" — is the exception that
swallows the rule, and the guard that enforces it does not have a clock.

**The decision in ADR-042 is unchanged and was right.** Its Context, Decision and Alternatives
are restated below verbatim in substance; only the three Consequences claims move.

## Decision

Unchanged from ADR-042, restated so that this document stands alone:

**A target is reduced to one canonical form once, at planning, and `scan_tasks.task_target` holds
that form.** Classification lives in `internal/target`, a leaf package both Core and the scan
point runtime import. `internal/scope` matches a canonical target against operator-written rules
and does nothing else.

`internal/target.Canonicalise` produces one string per host — trimmed, length-bounded, URL
unwrapped to its host, port and brackets and root label removed, address unmapped and
zone-stripped, prefix masked, hostname lowercased — or an error. ADR-040's refusal happens at
planning.

Rules are **not** canonicalised. They are policy text an operator wrote, and ADR-039's translated
forms mean one rule legitimately matches several addresses.

**The scan point re-canonicalises and compares. It does not validate.**

```
c, ok := target.Matches(received)   // ok iff Canonicalise(received) == received, byte for byte
```

A runtime that asked *"is this string canonical?"* would accept a canonical form of the **wrong
host**, which is what a bug in Core's canonicalisation produces. Asking *"does my own
canonicalisation of this string equal the string?"* makes the second site an independent
computation whose result is allowed to disagree, which is what ADR-024 requires.

**The comparison is against the received bytes, unchanged** — no trimming, no case folding, no
tidying before the equality test.

## The three corrections

**1. A canonicalisation mismatch is NOT reported separately from a scope violation.**

ADR-042 said:

> The audit event says so explicitly rather than reporting it as a scope violation, because the
> operator response is different.

It does not. Both refuse with `TerminationReason_SCOPE_VIOLATION_HALT`, at both sites, because
the wire enum is frozen and a new `termination_reason` is a proto change (ADR-022) — and
inventing a wire value to carry a distinction that belongs in a message is not a trade worth
making.

The distinction is real and worth keeping, so it travels in `JobTerminal.detail`, which the
proto already defines as *"operator-facing detail: which engine failed, which target halted the
scan"*. **Core did not read that field at all** — the compliance pass found it produced and never
consumed, for every terminal reason, not just this one. Core now persists it on the
`job.terminated` audit event, which is where an operator reads which of the two happened: a scope
violation means the policy and the plan disagree, a canonicalisation mismatch means something
between Core and the scan point changed the string.

**2. `internal/target` had no tests.**

ADR-042 said the classification moved there and was "tested there". It was not: the package had
no test file, and the apparatus three consecutive scan-safety audits found bypasses in —
`LooksLikeAddress`, the digit folding, the port and bracket handling — was covered only
indirectly, through conformance drivers in three other packages. `LooksLikeAddress` is exported
and had no direct test at all.

It has them now, and they are the ones that matter for a leaf package two enforcement sites
depend on: idempotence of `Canonicalise`, the equality property of `Matches` against unchanged
bytes, the component-based shape test in both directions, and the notation groups that must
collapse to one form.

**3. The Core conformance driver was a paraphrase of the wrong expression.**

Not an ADR-042 claim, but the same pass found it and it is the reason the first two mattered.
`internal/dispatch/scope_conformance_test.go` carried a comment saying it was "deliberately the
expression `offerWork` uses, not a paraphrase of it" — and it called `Canonicalise` where
`offerWork` calls `Matches`. Those give opposite answers for every non-canonical string, so the
Core half of ADR-024's two-site agreement was asserted against a code path Core does not run.

The driver now runs both steps in order: planning canonicalises the table's operator string, and
then `offerWork`'s real expression runs over what planning stored.

## Consequences

Everything ADR-042's Consequences said, except the corrected claim, still holds: `internal/scope`
is smaller, a target has one spelling by the time anything acts on it, `scan_tasks.task_target`
is still free text with both consumers re-deriving, and `scopetest` drives both sites.

**ADR-040's Consequences are now actively misleading and it is marked accordingly.** Its
"the normalised host is computed and then discarded" paragraph describes a landmine this decision
closed, and prescribes as the fix the first alternative ADR-042 rejected — so a session that
reads ADR-040 to find out what to do about per-target budgets is pointed at the rejected design.
ADR-040's status line names this ADR; its body is left as written, because that is what the rule
about editing accepted ADRs means.

**Two ADRs one session apart, the second superseding the first over three sentences, is noise in
the index.** That is the cost of the rule and it is worth paying. The alternative is a codebase
where a document's age decides whether it can be quietly rewritten, and the whole value of a
frozen ADR is that it records what was believed at the time — including, here, that its author
believed a control existed which did not.

## Review trigger

Same as ADR-042's: a target type with no single canonical form — a repository URL, a container
image reference, a cloud resource ARN. Additionally, if a `termination_reason` is ever added for
a non-scope refusal, correction 1 above stops being a workaround and this decision should say so.
