# ADR-047: The discovery engine may open sockets, and connect scanning is what it may do with them

**Status:** Accepted
**Date:** 2026-09-04

## Context

`internal/enginepolicy` is an allowlist: a package under `internal/engines` may import only what
it names, and everything else fails the build. Its exceptions map was written empty, with a
comment addressed to this session:

> The discovery engine will need raw sockets. When that session arrives there are two outcomes:
> someone adds an entry here — deliberately, in a diff a reviewer sees, with an ADR explaining why
> that engine may send packets and how ADR-024's ceilings bind it — or someone deletes this file
> because it is in the way.

This is that entry. The guard fired on the first build of the discovery engine and named the
requirement, which is the mechanism working rather than an obstacle.

`docs/execution-plan.md` §2 puts "TCP connect and SYN scanning" in the MVP, and this ADR ships one
of them.

## Decision

### `internal/engines/discovery` may import `net`, and nothing else

One import, to the logic package. The process shell `cmd/cvap-engine-discovery` gets `os` and
`internal/enginewire`, exactly as the no-op engine's shell does and for the same reason: this
binary needs its pipes, and a package that may import `os` is a package that could import
`os/exec`. Splitting them keeps the logic package's exception to a single line.

Deliberately **not** granted: `os/exec`, `syscall`, `golang.org/x/net/*`, `os/signal`. The engine
handles no signals, which is what keeps `syscall` — the raw-socket path — off the list.

### TCP connect scanning, and nothing else

Connect completes the handshake through the ordinary socket API, which is all `net` provides.

### SYN, ARP and ICMP are DEFERRED, not cut

§2 says "ARP, ICMP and TCP host discovery. TCP connect and SYN scanning" and this ships TCP
connect. A deferral with a named unblocker, recorded in `docs/execution-plan.md` §6.5 as well as
here.

**The line is coherent rather than arbitrary: `net` gives TCP connect, and every other discovery
method needs a socket the standard library will not create.**

- **SYN and ARP** need raw sockets and `CAP_NET_RAW`. That changes how a scan point is **deployed**
  — a privileged container, a file capability, a setcap step — and not merely what it can do.
  Bundling a deployment-model change with the first engine that can send anything at all means two
  hard things get one review.
- **ICMP** needs an unprivileged `SOCK_DGRAM` ICMP socket, which the kernel will grant without
  `CAP_NET_RAW` — but which **Go's standard library has no way to ask for**. Reaching it needs
  `golang.org/x/net/icmp` or `syscall`, and both are wider exceptions than the single `net` this
  ADR argues for. `syscall` especially: it is the raw-socket path the whole deferral exists to keep
  out.

  This ADR said the opposite in its first draft, and the code under it was written and merged into
  the working tree before being run. `net.ListenPacket("udp4", …)` does not create an ICMP socket;
  it creates a UDP one, and with the address form used it did not do that either. The path returned
  "unavailable" on every call and fell through to TCP — a discovery method that silently does
  nothing, which is the under-reporting-that-looks-complete failure this codebase weighs heaviest.
  It was found by running the engine against the lab and noticing the method recorded on the
  observation was never `icmp-echo`. Removed rather than repaired, because repairing it means
  taking the wider exception.

**The detection cost is real and accepted, not unnoticed.** Connect completes the three-way
handshake, so it is louder against anything watching and slower against a filtered host, where SYN
would get a RST or nothing quickly and connect waits out the timeout. And **a fully filtered host
is indistinguishable from an absent one** over connect scanning. The engine carries that honestly:
a negative host result names the method that produced it and carries a confidence below 1, because
"nothing answered" is weaker evidence than "something did" and reporting it as fact would be a
claim the method cannot support.

**What unblocks it:** a decision on how a scan point acquires `CAP_NET_RAW`, recorded as its own
ADR, plus an answer to how `make safety` proves a raw-socket engine stays in scope. The second is
the harder half — the connect path is observable through the socket API, and a raw sender is not,
so the egress-capture gate becomes the only evidence rather than one of two.

### How ADR-024's ceilings bind it

Every ceiling reaches the component that sends, because one that does not is decorative:

- **Rate.** The runtime allocates a slice and the engine's token bucket *is* that slice. The engine
  never reads the platform ceiling and does not coordinate with any other engine; the aggregate is
  bounded by what was handed out (ADR-027).
- **Adaptive means downward only.** Timeouts — not refusals, which are a closed port and say
  nothing about a host's health — halve the rate against that target. Nothing raises it. An
  adaptive limiter that could climb would be the engine deciding its own budget, which is what the
  allocation model exists to prevent.
- **Fragile** is already folded into the slice by the runtime, so the 10 pps cap applies here
  without this engine knowing the number.
- **Concurrency and connect timeout** travel in the job and are applied per target.
- **One target at a time**, concurrent within it. ADR-024's ceilings are per *target*; scanning
  several hosts at once would need a bucket each against a shared slice, which is the
  shared-mutable-rate-state arrangement ADR-027 rejects between processes and is no better inside
  one.
- The rate token is taken **before** the goroutine starts, so the budget governs how fast work is
  created rather than how fast it finishes — otherwise the concurrency cap's worth of goroutines
  start together and then queue, which is a burst at the host followed by a wait.

### Safe mode is enforced by withholding, not by a flag

ADR-021 makes safe the default for every policy, so it is the mode most deployments run and the one
that must be unable to provoke anything. The probe corpus lives in the **runtime**; a safe job is
handed an empty list. There is no corpus in this engine, so "safe mode" is not a branch here that a
bug or a rule could route around — there is nothing to send. Same shape as the rate budget.

`SafetyMode` still travels, for **provenance only**: every observation records it, and banners
record whether they were solicited. A service identified from what it volunteered and one drawn out
by a payload are different confidence levels, and the finding pipeline has to be able to tell.

The concrete cost, worth naming because it will surprise someone: **HTTP does not volunteer**, so
under a safe job a web server is an open port with no service attached.

### It holds no scope data

Targets arrive resolved and pre-authorised. No allowlist, no exclusions, no CIDR arithmetic. A
probe payload may carry a `{{target}}` placeholder that the engine substitutes with the address it
was already given, so the only address a probe can name is one the runtime authorised — an engine
composing its own would be constructing targets, which ADR-027 forbids.

## Alternatives considered

**Raw sockets now, and ship SYN with connect.** Matches §2 exactly and avoids a deferral. Rejected
above: it is a deployment-model change riding along with the first packet-emitting engine, and the
safety gate that would have to prove it correct is the same gate this session is bringing forward
from week 8. Two unproven things checking each other.

**Put the socket in the runtime and keep `net` out of every engine.** Tempting, because it would
leave the allowlist's exceptions map empty and the "no engine can send" property intact. Rejected:
it makes the runtime the scanner and the engine a configuration file, which is ADR-027 inverted —
and the runtime is also the component holding credentials and the scope decision, so it is the last
place to add a parser for hostile input.

**Shell out to nmap.** Mature, fast, and somebody else's maintenance. Rejected on ADR-025's line
and on this one: it needs `os/exec`, which is a far wider exception than `net`; its rate control is
its own rather than the runtime's allocation, so ADR-024's ceilings would become advisory; and its
output is a parsing surface as hostile as the network it read from.

**`golang.org/x/net/icmp` for the echo.** Correct, maintained, handles IPv6, and it is the only
way to get unprivileged ICMP in Go short of `syscall`. Rejected for the size of the exception
rather than the quality of the library: it is a dependency granted to the one package permitted to
open a socket, and it reaches `x/sys` to do it. Worth revisiting in the session that decides
`CAP_NET_RAW`, where the socket question is already open — which is the argument for deferring all
three together rather than taking ICMP's exception now and the other two later.

## Consequences

**The exceptions map is no longer empty, and that is the risk this decision creates.** The first
entry is the expensive one to argue for; the second is a smaller step, and the tenth is a habit.
The mitigation is that each entry names one package and one import, so a widening is visible as a
diff rather than as a policy that quietly stopped meaning anything — and the guard's failure
message still says that deleting it is the other way to make the build pass and is the wrong one.

**A host that answers nothing on the discovery port list is reported not alive**, and TCP connect
cannot tell that from a host that is filtered or absent. The observation records the method and a
confidence below 1, which is the most the method supports. ICMP would have narrowed this, and it is
the first thing the deferral costs.

**The default port set is ~180, not the top 1000.** §2 asks for the top 1000, and what ships covers
every service the MVP's finding rules reason about. The full list is empirical frequency data that
belongs in a data file beside the fingerprint corpus, not as a literal in source; shipping a padded
list that *looked* like the top 1000 would make the gap invisible. Recorded in §6.5.

**`make safety` is brought forward from week 8** in narrow form — egress capture in a network
namespace, asserting nothing leaves `lab/scope.txt`. It is week 8 in the plan because that is when
there was expected to be something to test; there is now, and a first packet-emitting engine
running with the gate still stubbed is the wrong order.

## Review trigger

The SYN/ARP session, which is where `CAP_NET_RAW` gets decided and where this ADR's deferral is
discharged. Also: a **second** engine asking for `net`, which is the moment to check whether the
exception is still per-engine or has become the rule.
