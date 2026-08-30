# ADR-021: Safe mode default; detection without impact

**Status:** Accepted
**Date:** 2026-08-30

## Context

Vulnerability verification sits on a spectrum from inference to full exploitation. Customers
must point this tool at production — that is where their exposure is — and an assessment tool
that achieves impact on production is one they will run once, in a lab, and never again.
Findings are also routinely disputed by the application team that owns the target, so how a
verdict was established is part of whether it holds up.

## Decision

Checks establish **evidence of a vulnerability without achieving impact**. Safe mode is the
default for every scan policy (`SCAN_POLICY.safety_mode`). Concretely:

| Class | Do | Do not |
|---|---|---|
| SQL injection | Boolean and timing differentials, error-based inference | Extract table contents |
| SSRF | Callback to our own out-of-band collaborator domain | Enumerate internal services |
| Command injection | Benign echo with a nonce | Spawn a shell |
| File inclusion | Prove the path is reachable | Exfiltrate file contents |
| Deserialization | Prove the sink is reached | Execute a payload |

No data extraction, no shells, no exfiltration. This is a property of the detection logic
itself, enforced in rule authoring and review, and is distinct from the operational blast-
radius controls in ADR-024.

**What `intrusive` means.** `SCAN_POLICY.safety_mode` takes `safe` or `intrusive`, and the
line between them is **disruption, not compromise**. `intrusive` permits checks that may
degrade availability or write to the target: full port ranges rather than top-N, brute-force
credential checks against a wordlist, protocol fuzzing, and checks that will trip an IDS. It
does **not** permit exploitation, data extraction, or shells — the table above binds in both
modes. Safe mode is the default for every policy; `intrusive` requires explicit per-scan
opt-in and emits an audit event on selection.

`safety_mode` and `reassign_safe` (ADR-012) are **orthogonal axes**. `safety_mode` governs
which checks are permitted; `reassign_safe` governs whether a lost job may retry. Active DAST
is safe-mode-permitted and **not** `reassign_safe`, because double-running it doubles load on a
live application. An intrusive port sweep may well be `reassign_safe`. Neither field implies
the other.

## Alternatives considered

**Full exploitation for verification, to eliminate false positives.** The strongest possible
evidence, and it is what a penetration test does. Rejected: it makes the tool unsafe to point
at production, which is the only place it needs to run; it converts an assessment product
into something requiring per-engagement legal authorisation; and it means our own scanner
holds working exploit capability against every customer estate — a threat model consequence
we decline to take on.

**Exploitation available behind a policy flag, off by default.** Superficially reasonable,
and rejected for v1 because a flag that exists will be enabled: the safety property has to
hold for the fleet, not for the default configuration. If we ever offer it, it belongs behind
explicit per-engagement consent, which is the review trigger below. Note that this is *not*
what `safety_mode: intrusive` is — intrusive buys disruption, never compromise.

**Collapse `safe` and `intrusive` into one mode and always scan conservatively.** Removes a
field and an opt-in path. Rejected: full port sweeps and credential brute-force are legitimate
assessment techniques a customer may knowingly authorise against their own estate, and
refusing them entirely pushes customers to a second tool. The opt-in plus audit event is what
keeps the decision theirs and recorded.

**Pure version inference with no active probing at all.** Safest, and it gives up DAST
entirely — boolean and timing differentials are the only way to establish an injection
finding without a CVE to point at. Evidence-without-impact is the line that keeps the
capability while keeping production safe.

## Consequences

The product is safe to point at production, which is what customers must do. Findings stay
defensible when disputed, because the evidence is an observed differential rather than an
assertion. Rule authoring gains a hard constraint that review must enforce, and the
`scan-safety-auditor` subagent exists for exactly this. The cost is a small class of
vulnerabilities that can only be confirmed by exploitation and which we will therefore report
at lower confidence, or not at all.

## Review trigger

Only if we offer authenticated exploit verification as a separately-consented product mode.
