# ADR-109: A scan target is an instruction, not a declaration of the subnet mask

**Status:** Accepted
**Date:** 2026-09-30
**Supersedes:** ADR-108's decision 4, in one word. That decision said the network and
broadcast addresses of a scanned CIDR are "refused outright, **whatever answered there**".
The arithmetic stands; the absolutism does not. Every other decision in ADR-108 is
unchanged, and decisions 5, 6 and 7 are what made this correction cheap.
**Follows:** ADR-108, whose own review trigger predicted exactly this — *"revisit when a
real host is suppressed and an operator has to argue with the verdict"*. It took one run.

## Context

ADR-108 was implemented and run once against the two authorised /24s. It suppressed a real
host.

```
10.200.10.15   22/tcp   Dropbear SSH 2024.85   (identification_method: banner)
```

It was suppressed as the broadcast address of `10.200.10.0/28`, which is a genuine entry in
`scan_targets`. A broadcast address does not run an SSH daemon that announces its version.

The same estate has been scanned as `10.200.10.0/23`, as `10.200.10.0/24` and
`10.200.11.0/24`, **and** as `10.200.10.0/28`. Under the first three, `.15` is an ordinary
host address. Under the last, it is the broadcast. The rule asked "is this the broadcast of
any scanned prefix?" and got "yes", which was arithmetically true and substantively wrong.

The mistake is not in the arithmetic. It is in the premise:

> **A scan target is an instruction about what to probe. It is not a statement about where
> the subnet boundaries are.**

An operator narrowing a scan to a /28 is saying "look at these sixteen addresses", not
"this network is a /28". CVAP does not learn the subnet mask from a scan request, and
nothing in `scan_targets` was ever intended to carry it.

## Decision

**1. A service that identified itself outranks the prefix arithmetic.** An address carrying
an identified service is `present`, whatever prefix arithmetic says about it. Positive
evidence beats an inference drawn from a range somebody chose to scan. Ordering, now:
identification, then impossible-address, then the range-wide responder signature.

**2. The arithmetic still decides when it is the only evidence.** An unidentified address
that is the network or broadcast address of a scanned prefix is still `responder`. Nothing
has shown itself to be a host there, and the arithmetic is the only thing the system knows;
withdrawing it entirely would put the four genuine phantoms of the measured estate back
into the inventory to avoid one false suppression.

**3. "An identified address is never suppressed" is an invariant with a test, not a line
order.** The violation *was* a line order, and a line order is not a guarantee — the next
edit reorders it back. The guard enumerates the hostile combinations (network address,
broadcast, broadcast of a narrower scanned prefix, every port a responder artefact, and
those in combination) and asserts the verdict is never `responder`.

## What this does not fix, stated rather than left to be discovered

A real host at an address that is the broadcast of the *actual* subnet and which never
identifies itself is still suppressed, and correctly so on the evidence available. The
converse also remains: if the real network is a `/23` and a host sits at `10.200.10.255`
with no identified service, the `/24` in `scan_targets` will suppress it. CVAP has no source
of truth for the subnet mask, so this cannot be resolved by reasoning — it needs the mask,
from the scan point's own interface configuration or from an operator. That is a capability
decision, not a rule change, and it is not made here.

The honest position is that the arithmetic is a heuristic wearing the clothes of a
certainty. It earns its place because it caught four true phantoms and, after this ADR,
costs nothing when it is wrong about a host that can speak for itself.

## Alternatives considered

**Only trust the widest scanned prefix containing the address.** Under `/23`, `.15` is an
ordinary host and the false suppression disappears — but so does the true suppression of
`10.200.10.255`, which is the broadcast of the `/24` and an ordinary host under the `/23`.
It trades a false positive for a false negative with no new evidence, and false negatives in
an inventory are the more expensive direction: a phantom host in the estate is visible and
arguable, a real host silently absent is neither.

**Require the address to be network-or-broadcast of *every* containing prefix.** The same
trade as above, arrived at more elaborately, and it degrades as soon as an operator scans
one narrow range.

**Withdraw the impossible-address check entirely.** Rejected by measurement: it is the only
thing that caught `10.200.10.0`, `10.200.10.255`, `10.200.11.0` and `10.200.11.255`, none of
which can be hosts and all four of which were assets.

**Infer the subnet mask from the address distribution.** Rejected as invention. A rule that
guessed the mask from which addresses answered would be deriving topology from the very
responses that are known to be untrustworthy on this estate — the middlebox answers across
the whole range, so the distribution it produces looks like one flat network whatever the
real masks are.

## Consequences

Re-measured on the same estate immediately after the change:

| verdict | addresses | of those, carrying an identified product |
|---|---|---|
| `present` | 29 | **29** |
| `responder` | 254 | **0** |
| `unknown` | 229 | **0** |

`present` is now exactly the population that identified itself, independently counted, and
**no suppressed address carries an identified service**. Before the fix it was 28 present
and one identified host suppressed.

ADR-108's decisions 5, 6 and 7 are why this cost an hour rather than a re-scan: nothing had
been deleted, so the suppressed host was still there with its services intact; the reason
was recorded on the row, so the argument was settleable by reading it; and the rule is pure,
so the corrected verdict was replayed over stored evidence with no network traffic at all.
That was the case for those three decisions, made in the abstract a day ago and collected
today.

## Review trigger

Revisit when the subnet mask becomes available — from a scan point's interface
configuration, from an operator-declared network inventory, or from a routing table. At that
point the arithmetic stops being a heuristic and decisions 1 and 2 can be re-examined
against something that actually knows where the boundaries are.
