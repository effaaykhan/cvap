# ADR-040: A target that names an address must parse as one, or the job is refused

**Status:** Accepted; consequences amended by ADR-044
**Date:** 2026-09-03

## Context

`internal/scope` decided a target by trying to parse it as an IP address and, on failure,
falling through to case-insensitive string equality against hostname rules. That fallback is
the wrong matcher for a string that names an address.

`192.0.2.5:443`, `[192.0.2.5]`, `192.0.2.5.` and `192.000.2.5` all name one host. None parses
through `netip`, so none could be reached by any address or CIDR exclusion — while a
`hostname`- or `url`-typed allow carrying the identical string matched them exactly. A
scan-safety audit demonstrated the result through supported configuration: an operator's
exclusion of a device is walked past by writing that device's address with a port.

The obvious repair — refuse every target that will not parse as an address — refuses
`scanner.example.com`, which is a legitimate target and always was. The set that must be
refused is narrower than "unparseable": it is strings that *name an address* and fail to parse
as one.

## Decision

A task target is classified before it is matched, in three branches.

1. **Normalise, then parse.** A port, surrounding brackets and the DNS root label are stripped
   first, because none of them changes which host is reached — the same argument ADR-039 uses
   to keep `::ffff:0:0/96` a notation rather than a route. A URL is unwrapped to its host, so a
   `url`-typed target is judged on the host it would reach rather than on its own punctuation.
   If what remains parses as an address or a prefix, the target **is** an address and IP rules
   apply to it.

2. **It plainly is not an address.** Hostname equality, exactly as before.

3. **It looks like an address and will not parse.** The job is **refused**, with the reason in
   the audit event, and the target is never compared as a hostname.

The third branch closes the bypass, and it fails the **job**, not the target. Dropping the
offending target and scanning the rest would report a clean run over coverage the scan did not
have, which is the failure this codebase refuses everywhere else — `ErrTooManyTasks`,
`scopePlan`'s unexpressible rules and the runtime's out-of-scope refusal all take the same
position, and for the same reason: under-scanning that looks complete is the worst outcome
here, because the customer acts on it.

**"Looks like an address" is a test on the COMPONENTS, not on the character set.** The first
cut asked whether the string was digits, dots and slashes — which is an enumeration of two
spellings, the very failure this ADR rejects two paragraphs below, and an audit walked past it
with `0xC0000205`, `0xC0.0x00.0x02.0x05`, `192.0.0x2.5`, `192.0.2.1-50`, `192.0.2.5,192.0.2.6`
and fullwidth digits. Each reaches 192.0.2.5, or a range containing it, under `inet_aton`
semantics.

The question that generalises is whether every *component* is a number. Split on the separators
an address or an address range can use — dot, slash, hyphen, comma — and ask whether each piece
parses as an integer in some base. `strconv.ParseUint` with base 0 accepts decimal, `0`-octal
and `0x`-hex in one call, which is the set `inet_aton` accepts.

That does not over-refuse hostnames, because **bare hex is not a number**: `dead.beef` and
`cafe.example` remain hostnames while `0xdead.0xbeef` does not, and `1host.corp.example` stays a
hostname for the same reason — which is why the obvious leading-digit test was wrong. Unicode
decimal digits are folded to ASCII for the shape test only, because UTS-46 maps them before
resolution; the unfolded string is what gets parsed, so a folded-only match ends in a refusal
rather than a silent reinterpretation.

A colon or a bracket remains decisive on its own. **Brackets are consumed by normalisation, so
the fact of them travels separately** — otherwise `[ 192.0.2.5 ]` loses its strongest signal
before the test runs.

**A URL is judged on the host it would reach, in both directions.** Excluding
`printer.corp.example` covers `https://printer.corp.example/setup`; allowing
`scanner.corp.example` authorises `https://scanner.corp.example/status`.

This was drafted as an asymmetry — exclusions reach the host, allows do not — and the audit
showed the code neither implemented it nor could: `addr` comes from the normalised host and the
address branch never looks at the string, so a `cidr` allow already authorised every URL on that
address. The asymmetry held for hostname URLs alone, which made the rule depend on what the host
happened to be. Judged on the host in both directions is the coherent rule: **scope authorises
hosts.** If the packet reaches a host the operator allowed, the URL is in scope; if it reaches
one they excluded, it is not. What is *requested* from that host is `safety_mode`'s question
(ADR-021), not this one. ADR-039's allow/deny asymmetry is untouched and still belongs where it
is — a translated form reaches a host through infrastructure the operator may not own, which a
path on an already-authorised host does not.

## Alternatives considered

**Refuse every target that does not parse as an address.** One rule, no shape heuristic, and
trivially correct about the bypass. Rejected: it refuses every hostname target, and hostname is
an accepted `scope_match_type` with rules already written against it. Fixing an exclusion gap
by making a whole match type unusable is not a fix.

**Normalise and keep falling through to hostname equality.** Strip the port and brackets, then
carry on as before. Rejected: it closes the three notations someone thought of and leaves the
class open. `192.000.2.5` still reaches hostname equality, and so does whatever notation the
next audit finds — the same enumeration failure that made `protect-contracts.py` list ways to
write a file rather than ask whether one changed.

**Refuse at planning only, in `scopePlan`.** Validate `scan_tasks.task_target` when the
assignment is built and leave the matcher alone. Rejected: `task_target` is free text with no
constraint tying it to its `scan_targets.target_value`, so a planning bug can put anything
there — and the scan point runtime is the second enforcement site precisely because Core's
check may be wrong or old. A rule enforced at one site is the arrangement ADR-024 rejected.

**Resolve the target and compare the result.** `192.0.2.5:443` and `192.0.2.5` resolve
identically; so would a hostname and its address. Rejected for the reason `scopeMatches`
already gives for not resolving DNS: a resolution done at decision time is a different answer
from the one the scan point would get, and an allowlist that depends on which side asked is not
an allowlist.

## Consequences

An exclusion now reaches a host however its address is spelled, which is what an operator
excluding a device believes they have done.

A malformed target fails its job loudly instead of being silently compared as a hostname and
silently missing every address rule. That is a new way for a job to fail, and it is meant to
be: the audit event names the target, and a planner producing `192.000.2.5` has a defect worth
seeing rather than a scan quietly running outside its exclusions.

`looksLikeAddress` is a heuristic and will misjudge something eventually. Both of its errors
are survivable and neither is silent: a hostname wrongly called address-shaped fails its job
with the string in the audit event, and an address wrongly called a hostname behaves as it did
before this ADR. It errs toward refusing, which is the direction a scope decision should.

Two known over-refusals, both loud: a literal un-percent-encoded IPv6 zone in a URL
(`https://[fe80::1%eth0]/` — the `%25` form is fine), and any non-address target carrying a
colon that is not a port, such as a JDBC connection string. Both fail their job with the target
named.

**The normalised host is computed and then discarded.** `192.0.2.5`, `192.0.2.5:443`,
`192.0.2.5.`, `[192.0.2.5]` and `https://192.0.2.5/` all pass the gate as five distinct target
strings naming one host, and an engine receives the string it was given. Nothing keys a rate or
concurrency budget on a target yet, so this is a landmine rather than a defect — but ADR-024's
per-target ceilings and the `fragile` cap would each divide by the number of spellings present
in one job. The fix is to hand the caller the normalised host; it belongs with whichever session
first implements a per-target budget.

The normalisation is confined to notation that does not change the destination. It does not
strip a path, a query or a fragment from a URL — those select what is requested from a host,
not which host — and it does not touch userinfo, which would change who the request
authenticates as.

## Review trigger

A target shape that is neither an address nor a hostname and is legitimately scannable — a
repository URL for SAST, a cloud resource ARN, a container image reference. Each names
something that is not reached by IP at all, and the classification above has no branch for
them: they would need a match type that does not pretend to be about addresses.
