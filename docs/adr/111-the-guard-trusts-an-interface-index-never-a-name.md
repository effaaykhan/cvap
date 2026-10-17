# ADR-111: The guard trusts an interface index, never a name — and the exempt set must be the refused set

**Status:** Accepted
**Date:** 2026-10-13
**Supersedes:** ADR-110's statement that an interface added by `docker network connect`
"carries nothing until the holder has policed and verified it" (which was false for a
*reconnected* interface), its "every second by default, also its HEALTHCHECK" (the
HEALTHCHECK runs every 5 s), its wording "enabling them is a change to this ADR" (a
committed ADR is superseded, never changed), and the implied claim that P4 — the exempt set
being exactly the configured Core endpoints — was enough. Every other decision in ADR-110
stands: the invariant, R and B, the enforcement topology, P1–P5 as stated, and the
consequences.
**Follows:** ADR-110, and the three read-only reviews of it (scan-safety, security,
ADR-compliance), two of which measured the first finding below independently.

## Context

ADR-110 was committed with a passing gate and reviewed. The reviews found one critical and
one high defect, both in the space between what the ADR *said* and what the code *checked*.

**1. The guard admitted a reconnected interface unpoliced.** The nftables guard's `policed`
set was keyed by interface **name**, and nothing ever removed a name. `docker network
disconnect` destroys the interface and its tc state; `connect` creates a new one under the
same name (`eth1`), with no filters, offload on and a default `gso_max_segs`. The guard saw a
name it knew and accepted; `attach` saw a name already in the set and skipped policing. Only
the next verify noticed, and the holder then exited — correctly, but late. Measured by two
reviewers independently: 4,594 UDP superpackets (a protocol P2 says never leaves) reached
the wire in 0.59 s; with `CVAP_NP_VERIFY_SECONDS` unbounded the window was as long as the
operator had set. The operator triggers this by following INSTALL §6 ("connect it to the
holder") after any earlier disconnect.

**2. Nothing tied the exempt set to the refused set.** The holder exempts TCP to E, typed by
the operator as IP literals. The Scan Point refuses as targets the addresses *it* resolved
for Core. ADR-110 rested on those being the same set ("a scan aimed at Core would ride it
unpoliced … Core endpoints are therefore refused") and nothing checked it. A typo, a NAT
address or a split-horizon answer gives an exempt `ip:8443` that nothing refuses: a scan
path outside the ceiling. The gate could not see it, because it handed the same E to both
sides.

Smaller findings from the same reviews are folded in below rather than left as a list.

## Decision

### The guard is keyed by interface index

- The `policed` sets are `type iface_index`. The kernel never reuses an index while a
  namespace lives (measured: a reconnected `eth1` came back as index 4, not 3), so a fresh
  interface can never already be a member. Guard rules match `oif @policed`.
- Every cycle `attach` **prunes** indices whose interface is gone and **re-verifies every
  live interface** before `verify` passes; set membership is never trusted on its own. The
  shared police action is **checked, never re-created**: an action that vanished means
  something with `NET_ADMIN` removed it, which is a failure to exit on, not repair.
- A pass is judged against a **stable interface set**. The holder snapshots the live
  interfaces (name, index and up/down flags) before a pass and after it, and every listing
  the pass itself takes is kept; a pass that fails while any two adjacent listings differ saw
  a changing set, not a failed check, and is run again at once, at most 5 times in a row.
  Comparing only the two ends was not enough: on the 59th reconnect cycle under load, eth1
  arrived after the opening snapshot and vanished before the closing one, both ends agreed,
  and the holder exited on `eth1 (ifindex ) is not in the policed set` — a failure the pass
  had caused by observing an interface neither snapshot held. A set that looks unchanged right after a failed
  pass is given 1 s to settle first, because Docker moves an interface in, renames it and
  brings it up in separate steps and a DOWN interface has no root qdisc to verify (measured:
  `gatev0: qdiscs are [clsact], not exactly clsact + noqueue` on an interface created DOWN).
  A failure on a set that did not change, or a set that keeps changing, still exits the
  holder, so a fault is fatal within `CVAP_NP_VERIFY_SECONDS` + 1 s. Measured before this: the
  holder exited on the fifth disconnect/reconnect cycle with `eth1: ethtool -k failed / eth1
  fails verification`, because eth1 vanished between `ifaces` listing it and `ethtool`
  reading it, which took the Scan Point's network down on an ordinary network restart.
  Nothing is admitted between passes: the guard drops everything leaving through an index not
  in the set, and only a verified interface is ever added.
- A **DOWN interface is not an egress interface.** It carries nothing and cannot verify (it
  has no root qdisc before its first up), and Docker moves a new interface in DOWN, under a
  temporary name, and brings it up in a later step. Measured under daemon load, with the
  gate's UDP_SEGMENT loop running in the namespace, that step came more than a second later,
  and the first version of the stable-set rule exited the holder on
  `vethd5ad60f: qdiscs are [clsact], not exactly clsact + noqueue` ...
  `verification failed on interfaces [eth0:2:0x1003 vethd5ad60f:133:0x1002 ] (pass 1)` — a
  set that had not changed, judged as a failed check, on the 27th reconnect cycle. `ifaces`
  now lists only UP interfaces: a DOWN one is neither verified nor admitted, it joins the
  policed set at its first UP pass, and until then the guard drops anything its index would
  carry — which, DOWN, is nothing. The settle second stays as a second line, not the fix.
- `CVAP_NP_VERIFY_SECONDS` is at most 5. It bounds how long any fault can go unnoticed and
  is not an operator's to widen.
- Measured after the fix, at the destination: zero UDP packets reached the peer across a
  disconnect/reconnect under a looping `UDP_SEGMENT` sender; the holder pruned the old index,
  policed the new one under its new index, and kept running. "At the destination" matters: a
  first measurement captured from a bystander container on the same bridge and saw nothing,
  which proved nothing - a Linux bridge forwards unicast only to the learned port, and the
  same bystander saw 0 of 200 datagrams the destination received. The gate captures inside
  the peer's namespace and proves that capture point each run with a TCP control that must be
  seen.

### The exempt set must be within the refused set

- The Scan Point reads the holder's `CVAP_NP_CORE_ENDPOINTS` verbatim. At startup it
  requires every exempt address to be among the Core addresses it resolved for itself, and
  **refuses to start** otherwise (`ErrExemptNotRefused`). An E it cannot parse is an error,
  never skipped. The check is one-directional: Core may be reachable at more addresses than
  the holder exempts.
- Compared by address identity after zone-stripping, as both sets are stored. An
  IPv4-mapped IPv6 endpoint spelling (`::ffff:10.0.0.5`, and every equivalent — the all-hex
  `::ffff:0a00:0005`, a fully expanded `0:0:0:0:0:ffff:…`) is **refused** rather than unmapped:
  the Scan Point rejects it (`netip.Addr.Is4In6`) and the holder's `is_ipv6` rejects it (by
  expanding the literal, not by looking for a dotted quad). Were one side to unmap it to IPv4
  while the other kept it as an IPv6 literal, the exempt set and the refused set would disagree
  about that one address's family; refusing the spelling on both sides keeps them the same set.
  Write a Core endpoint as a plain IPv4 or native IPv6 address.

### The Scan Point checks its own privilege

The deployment is *told* to run the Scan Point non-root with every capability dropped and
`no_new_privs` set (ADR-110 P3). The Scan Point now **checks that it was**, before touching
the network, in two halves. What it *has*: euid ≠ 0 and `CapInh`, `CapPrm`, `CapEff` and
`CapAmb` all zero, read from `/proc/self/status` (a status missing any line is not trusted;
permitted counts, not just effective — `CAP_NET_RAW` permitted is one `capset` from
effective). What it could *gain*: `no_new_privs` must be set — and the Scan Point makes it so itself,
first thing in `main`: if the flag is clear it sets it on a locked thread and re-executes
`/proc/self/exe`, so the surviving task carries the flag into the whole new process and
everything it ever execs. (A plain `prctl` is not enough: the flag is per *task*, a Go
program already has several threads, and the main thread's status still read 0 — measured,
the e2e harness's scan point refused itself after a successful `prctl`.) With it set no
`execve` confers a capability, setuid bit or file capability alike, whatever the bounding set
holds; a deployment that already set it (`--security-opt no-new-privileges`) never re-execs.
So the bounding set is **not** required empty: a non-root process cannot empty it (that
needs `CAP_SETPCAP`), and it is full for any process started outside a `--cap-drop ALL`
container — a developer's host, the e2e harness — where the self-set `no_new_privs` gives the
same guarantee. (A first version required `CapBnd` = 0 too and refused to start on any host;
measured by the e2e suite going red before any mutation.) The deployed container empties the
bounding set anyway, and the gate requires that of the deployed shape.

### The ceiling is lower-only, and E is one host per entry

- `CVAP_NP_RATE_PPS ≤ 1000`, `CVAP_NP_BURST ≤ 100`, refused at start otherwise — ADR-024's
  "a policy may lower it and may never raise it", applied to the holder's own knobs. (The
  gate uses the lower values it needs; nothing legitimate needs higher ones.)
- Each endpoint is **one** address: IPv4 as a dotted quad with no leading zeros (iproute2
  reads `010` as octal) and not `0.0.0.0`; IPv6 as hex and colons — no prefix, no zone, not
  `::`, and not an IPv4-mapped form (`::ffff:a.b.c.d` or its all-hex spelling), which is
  refused so it cannot be exempted as an IPv6 literal while the runtime unmaps it to IPv4. A
  prefix in E (`[fd00::/64]:8443` was accepted before, and exempted a /64) is refused. IPv4 and IPv6 may be mixed: each family has its own
  tc preference (1 and 2), because tc binds one preference to one protocol.
- The root qdisc of every egress interface must be exactly `noqueue` beside `clsact`; a
  classful or `netem` root could clone or reorder after classification, turning one charge
  into several packets.
- The holder itself runs with `--cap-drop ALL --cap-add NET_ADMIN --security-opt
  no-new-privileges`. It needs nothing else, and `NET_RAW` in any process of the namespace is
  the raw-frame bypass.

### The gate judges these at the wire, not only in configuration

- **reconnect:** disconnect and reconnect the second network under a looping `UDP_SEGMENT`
  sender; capture inside the PEER's namespace on the interface holding the destination
  address, which sees whatever reached it from the Scan Point's interface, new or old; first
  prove that capture point with TCP through the policed interface (`capture-control`), then
  require zero denied-protocol packets, the holder still running, and all preconditions
  holding afterwards. Its sabotage runs a holder rebuilt with the name-keyed guard put back,
  so the case is shown to fail against the defect and not merely to exercise a checker.
- **iface-removed-mid-pass:** the reconnect case first runs three quick disconnect/connect
  cycles with gaps shorter than a verify pass, and a deterministic case adds a veth pair
  inside the namespace, lets the holder police it, waits until the holder is between passes
  and then deletes the pair the instant the next pass's first `ethtool` appears, which is
  before the pair's own checks. The holder must still be running, have logged a re-verify,
  and every precondition must hold with the set naming only live interfaces. Its sabotage
  runs a holder rebuilt with `MAX_PASSES=0`, the pre-fix behaviour, which must be seen to
  exit.
- **iface-down-arrival:** a veth pair is added inside the namespace and left DOWN for 3.5 s,
  longer than a verify cycle plus the settle second. The holder must still be running, must
  not have admitted the DOWN interface to the policed set, must police both ends within a
  cycle of their coming up, and every precondition must hold after that and after the pair is
  removed. Its sabotage runs a holder rebuilt to list DOWN interfaces as before, which must be
  seen to exit.
- **second-iface:** TCP load through both interfaces, both veths captured, the captures
  merged and judged against a single B + R·Δ — "one bucket" measured, not asserted.
- **unpoliced-at-wire:** in the unpoliced-interface sabotage, which runs a holder rebuilt so
  its loop never re-attaches (a stalled holder — the real one would police the interface
  within its 5 s cycle and win the race), traffic aimed at the never-policed network must not
  leave — the guard's job, on a wire, captured at the destination. The guard-flushed sabotage
  runs the same capture with the inet guard flushed beside the same unpoliced interface and
  must see the leak, so that sabotage is judged by what reached the destination, not by
  reading the ruleset. (The peer's neighbour entry is seeded first: an IP packet is dropped
  at the output hook before it resolves a neighbour, so the still-intact ARP guard would
  otherwise hold the lookup and hide what the inet guard alone was holding. The ARP guard's
  own sabotage stays a ruleset check for the same reason — the only ARP a namespace without
  raw sockets can emit follows an IP packet the inet guard has already dropped.)
- **exempt-vs-refused:** `runtimedrive` given the holder's E must start; given an E naming an
  address Core did not resolve to, it must refuse before any engine exists.
- The Core-target wire check counts **every** TCP packet to Core, the exempt ports included:
  nothing in that phase talks to Core legitimately, and discovery's default ports include
  8443, so excluding it hid exactly the packets the check exists to catch.
- The lowered ceiling must fail **at least 35** of 100 connections (the arithmetic ADR-110
  stated and the gate did not assert), and the raw socket must be **refused** (EPERM), not
  merely fail to get frames out.
- The guard is checked exactly: both chains, hook `output` priority −300 policy accept, the
  verdict sequence, `oif @policed`, the loopback accept, and set type `iface_index`; the
  qdisc per interface; the Scan Point's uid; the holder's effective set being `NET_ADMIN`
  alone. New sabotages break each: a flushed guard chain, a removed ARP table, a `netem`
  root, a raised rate (the holder must refuse to start), a root Scan Point, the name-keyed
  guard, the holder without the mid-pass re-verify.

## Alternatives considered

**Prune names instead of keying by index.** Rejected: a name is pruned only when the holder
runs, and the reconnect happens between runs; the new interface carries the old name in that
gap. An index is never the same twice, so the gap closes by construction.

**Trust set membership and re-police only on verify failure.** Rejected: that is the
original design, and the window it leaves is the finding.

**Give the Scan Point `NET_ADMIN` to read tc state via netlink.** Rejected: P3 says no
capability, and a netlink dump needs none — but the simpler cross-check (E within the resolved
set) answers the question that matters without reading tc at all.

**Accept any ADR-110 wording and fix only the code.** Rejected: an ADR that says "carries
nothing until … verified" while the code admits a renamed interface is the drift that made
this review necessary. A committed ADR is superseded, never edited, so this ADR exists.

## Consequences

- **Operational:** the holder refuses to start above the platform ceiling, with a malformed
  or prefix endpoint, or with a verify interval above 5 s; the Scan Point refuses to start as
  root, with any capability, without `no_new_privs`, or with an exempt address it would not
  refuse. INSTALL §6 passes the same `CVAP_NP_CORE_ENDPOINTS` to both containers and starts
  the holder with `--cap-drop ALL`. Core also refuses to start if any of its certificate
  hosts (`CVAP_CORE_SERVER_HOSTS`, including `CVAP_EXTERNAL_HOST`) fails to resolve inside
  its container — a consequence of ADR-110's Core-side refusal that it did not state.
- **SYN/ARP discovery and any UDP-based discovery** are each a decision to supersede P2 or
  P3 of ADR-110 by a new ADR, not an engine change (`docs/execution-plan.md` §6.5 now says
  so).
- **Still not done:** the Scan Point does not verify the holder's tc/nft state itself; it
  verifies its own privilege and the exempt set, and relies on the holder's verify and the
  gate for the rest.

## Review trigger

Revisit when a kernel change alters interface-index allocation or `iface_index` set
semantics, when the Scan Point gains any socket type beyond TCP, or when a deployment needs
Core reachable at an address the Scan Point cannot resolve for itself.
