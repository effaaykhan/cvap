# ADR-042: Targets are canonicalised once at planning, and re-canonicalised at the scan point

**Status:** Superseded by ADR-044
**Date:** 2026-09-03

## Context

ADR-040 made `internal/scope` classify a target before matching it: strip a port, brackets and
the DNS root label, unwrap a URL to its host, decide whether what remains is an address, a
prefix or a hostname, and refuse the address-shaped strings that will not parse. It closed a
real bypass. It also put that whole apparatus inside the matcher, which runs at **both**
enforcement sites, on **every** target, on **every** rule comparison.

That has two costs, and one of them is recorded in ADR-040's own consequences.

The first: the normalised host is computed and thrown away. `192.0.2.5`, `192.0.2.5:443`,
`192.0.2.5.`, `[192.0.2.5]` and `https://192.0.2.5/` pass the gate as five distinct strings
naming one host, and an engine receives whichever spelling the row happened to hold. ADR-024's
per-target rate and concurrency ceilings, and ADR-021's `fragile` cap, each divide by the number
of spellings present in one job — five spellings of one fragile device get five budgets.

The second: three audits have found bypasses in the classification, and every one of them was
reachable *because the matcher accepted notation*. A matcher that accepts notation has to be
right about all of it, at both sites, forever.

`scan_tasks.task_target` is free text. Nothing constrains it to its `scan_targets.target_value`,
and nothing normalises it, because until this session nothing wrote it in production at all.

## Decision

**A target is reduced to one canonical form once, at planning, and `scan_tasks.task_target`
holds that form.** Classification moves out of `internal/scope` into `internal/target`, a leaf
package both Core and the scan point runtime import. `internal/scope` narrows to what it should
have been: matching a canonical target against operator-written rules.

`internal/target.Canonicalise` produces one string per host — trimmed, length-bounded, URL
unwrapped to its host, port and brackets and root label removed, address unmapped and
zone-stripped, prefix masked, hostname lowercased — or an error. ADR-040's refusal is unchanged
and now happens at planning, where the operator can be told about it, rather than at claim time.

Rules are **not** canonicalised. They are policy text an operator wrote, they are compared
rather than executed, and ADR-039's translated forms mean one rule legitimately matches several
addresses. The asymmetry is deliberate: the target side is reduced to one form because we
control it; the rule side stays as written because the operator does.

**The scan point re-canonicalises and compares. It does not validate.**

```
c, ok := target.Matches(received)   // ok iff Canonicalise(received) == received, byte for byte
```

This is the part that is easy to get subtly wrong, and the wrong version passes every test the
right one does. A runtime that asked *"is this string canonical?"* would accept a canonical form
of the **wrong host** — which is precisely what a bug in Core's canonicalisation produces, and
three sessions of scope findings say to expect one. Asking instead *"does my own canonicalisation
of this string equal the string?"* makes the second site an **independent computation whose
result is allowed to disagree**, which is what ADR-024's "neither side trusts the other"
actually requires. The comparison catches a target mutated in transit, a Core that skipped the
step, and a Core whose step produced something else.

One function run twice on two machines is not two implementations. What makes it a second
enforcement site is that the second run's answer can differ from the first's, and that the
difference stops the job.

**The comparison is against the received bytes, unchanged.** No trimming, no case folding, no
tidying before the equality test. Trimming first would make `" 192.0.2.5"` equal its own
canonical form — the exact "close enough" tolerance that distinguishes a validator from a
re-computation, and the defect the first draft of `Matches` actually had. A test in
`internal/scanpoint` holds this: eight in-allowlist targets that the matcher would happily
permit, each refused because the string is not the runtime's own canonical form of itself.

## Alternatives considered

**Leave classification in the matcher and hand the caller the normalised host.** ADR-040's own
suggested fix for the discarded host, and the smallest change. Rejected: it fixes the budget
landmine and leaves the larger one, which is that the matcher still accepts notation at both
sites and therefore still has to be right about all of it in two places. It also leaves
`task_target` free text, so the next planner bug still writes `192.000.2.5` into a row and the
matcher still has to catch it.

**Canonicalise at planning and have the runtime simply trust the value.** One computation, no
duplication, and Core is the component that holds the policy. Rejected outright: it is
single-site enforcement wearing a normalisation hat. ADR-024 added the second site because
Core's check may be wrong, old, or bypassed, and a value that arrives from the network with no
independent computation behind it is a value the runtime has accepted on Core's word.

**Canonicalise at planning and have the runtime validate the form.** Cheap, obvious, and it
reads as defence in depth. Rejected: it is the version this ADR exists to warn about. Validation
asks a property question about a string; the property holds for a canonical string naming any
host at all. It catches a garbled value and misses a wrong one, and a wrong one is what a
canonicalisation bug produces.

**Two implementations at the two sites, for genuine independence.** The strongest reading of
"neither side trusts the other" — a second implementation catches a bug in the first. Rejected:
two implementations of address notation will disagree about something neither author thought
about, and the disagreement is a scan point refusing work Core legitimately planned, in
production, at 3am. `internal/scope/scopetest` exists precisely because divergence between the
two sites is the failure mode this codebase most wants to avoid. One function, two machines,
compared results is the arrangement that catches transit mutation and skipped steps without
inventing a second notation dialect.

**Constrain `task_target` in SQL instead.** A CHECK constraint, or a FK to `scan_targets`.
Rejected as insufficient rather than wrong: no constraint expressible in SQL knows what
canonical means here, and a FK would still permit a canonical-looking string for the wrong host.
Worth revisiting as a defence-in-depth measure, not as this mechanism.

## Consequences

`internal/scope` gets smaller, and the shrink is the point. It no longer parses ports, brackets,
URLs, hex octets, fullwidth digits or the DNS root label. Those live in `internal/target`, run
once per target instead of once per rule comparison, and are tested there.

**A target now has one spelling by the time anything acts on it**, which is what makes ADR-024's
per-target ceilings and ADR-021's `fragile` cap countable. That was ADR-040's recorded landmine
and it is now closed.

`scan_tasks.task_target` is still free text at the database level, and this ADR does not change
that. What changed is that production code writes it in exactly one place and both consumers
re-derive rather than trust. The dispatch site re-computes for the same reason the runtime does:
a row can be written by something that skipped planning.

**The scan point can now refuse a job for a reason that is not about scope at all** — the target
was in the allowlist and was still refused, because it was not canonical. The audit event says
so explicitly rather than reporting it as a scope violation, because the operator response is
different: a scope violation means the policy and the plan disagree, and a canonicalisation
mismatch means something between Core and the scan point is wrong.

`internal/scope/scopetest` still drives both sites, but the two now enter differently: Core
canonicalises the table's raw target, and the runtime is handed the canonical value the wire
would carry. A table case that does not canonicalise is a denial at Core and never reaches a
scan point, which the runtime driver asserts rather than skips.

## Review trigger

A target type that has no single canonical form — a repository URL, a container image reference,
a cloud resource ARN. ADR-040's review trigger names the same class for the same reason: each
would need `Canonicalise` to have a branch that returns something other than a host, at which
point "one string per host" stops being the invariant this ADR rests on.
