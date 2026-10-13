# ADR-110: The Scan Point packet ceiling is enforced by the kernel, per network namespace

**Status:** Accepted
**Date:** 2026-10-13
**Follows:** ADR-024, which sets the 1,000 pps per-Scan-Point ceiling this ADR enforces, and
the M0.2 R2a work (commit `42f112e`), which admits each fingerprint operation's wire cost
before it starts. R2a bounds what the engine *intends* to send; this bounds what the
namespace *can* send, including everything the kernel sends on the engine's behalf.

## Context

ADR-024's per-Scan-Point ceiling was enforced in user space: the engines charge a budget for
the packets they model, and R2a admits each operation's modelled cost before it begins. That
model cannot cover packets the engine never writes — ACKs the kernel sends for a peer that
streams data, retransmissions, RSTs for sockets that are already gone, ICMP — and a peer
chooses how many of those it extracts. Three user-space designs were investigated and
rejected: a fixed per-operation cost model and a hybrid of it (R2-B: a peer that streams data
drives kernel-originated packets the model cannot bound), and a poll/abort loop that watches
counters and kills work (R2-C: no deterministic bound — it acts after the packets have left,
and its latency is the Go scheduler's). The bound has to be applied where every packet passes
and nothing is scheduled: the kernel's egress path.

## Decision

### The invariant

For every Scan Point network namespace N and every interval of length Δ seconds:

    P_non_core(N, Δ)  ≤  B + R·Δ        R = 1,000 packets/s,  B = 100 packets

P counts **every packet leaving any interface of N** — engine data, kernel ACKs,
retransmissions, RSTs, ICMP, ARP, IPv4 and IPv6 — except TCP to the Core endpoints E.

### Enforcement topology

- **A network-policy holder** (`deploy/netpolicy`) owns the namespace. It is the only
  process that holds `CAP_NET_ADMIN` there. The Scan Point joins its namespace with
  `--network container:<holder>` and holds no capabilities at all.
- **The charging point is tc's clsact egress hook** on every non-loopback interface of N,
  with ONE shared `police` action (`pkts_rate 1000 pkts_burst 100`, drop on exceed) — so a
  Scan Point attached to several networks still has one bucket.
- **The filter set is exact, in this order:** (pref 1) TCP to each Core endpoint `ip:port`,
  pass; (pref 10–14) IPv4 TCP, IPv4 ICMP, IPv6 TCP, ICMPv6 and ARP, each into the shared
  policer; (pref 100) everything else, drop. Unknown protocols are dropped, not charged:
  there is no exception list to fall through.
- **An nftables guard** (inet and arp output hooks, priority −300) drops anything leaving
  through an interface that is not yet in its `policed` set, so an interface added by
  `docker network connect` carries nothing until the holder has policed and verified it.
- **The holder keeps verifying** (every second by default, also its HEALTHCHECK), polices
  interfaces added since, and **exits on any failed check**. Docker then tears down the
  namespace's endpoints and the Scan Point is left with loopback only — measured: the
  Scan Point's next connect fails "network unreachable". Fail closed, not fail open.

### Preconditions — each one necessary, each one checked by the gate

The policer charges once per *buffer* (skb); the invariant is about *packets on the wire*.
The preconditions are what make those the same, and each closes a bypass that was measured,
not hypothesised:

| | Precondition | The bypass it closes (measured) |
|---|---|---|
| **P1** | On every egress interface: `gso_max_segs = 1`, `gso_max_size ≤ MTU`, every TX segmentation, scatter-gather and GRO feature off | TCP builds multi-segment buffers even with `ethtool gso off`. With TSO/GSO off only, one bulk-writing connection put ~6,000 full-size packets/s through a 1,000 pps policer (267 drops) |
| **P2** | The exact filter set above: Core exclusions, TCP/ICMP/ICMPv6/ARP into the shared policer, catch-all drop; and the nftables guard | `UDP_SEGMENT` (unprivileged) turns one buffer into up to 64 packets AFTER the hook, whatever the segmentation settings: at R=20, B=5 its 5 charges left as 320 packets, against a bound of 5 + 20·Δ. Only dropping UDP before it is charged closes it |
| **P3** | No capability in the Scan Point: `--cap-drop ALL`, `--security-opt no-new-privileges`, non-root; effective, permitted, inheritable, bounding and ambient sets all empty | `AF_PACKET` with `PACKET_QDISC_BYPASS` skips the tc egress hook entirely: 1,724 of 2,000 frames sent were captured on the wire, policer counter 0. It needs `CAP_NET_RAW`, which Docker grants root by default |
| **P4** | E is exactly the configured Core endpoints, as IP literals with ports (names refused) | A wider exclusion is an unpoliced path: a flower `pass` for one target put 64,704 packets in 3 s on the wire against 3,100 |
| **P5** | Forwarding off: `net.ipv4.ip_forward`, and IPv4/IPv6 forwarding for all, default and each interface | A forwarded buffer may arrive already merged and leave as one charge. `/proc/sys` is read-only in a container, so the holder is started with `--sysctl` and refuses to run otherwise |

### Core is never a scan target

The exclusion is TCP to E only, so a scan aimed at Core would ride it unpoliced. Core
endpoints are therefore refused as targets at both ADR-024 sites (commit `26aea5d`): Core's
dispatch refuses a task whose canonical target is, or as a prefix covers, a Core endpoint
address; the Scan Point runtime's `engineHost.authorise` refuses the same using the endpoints
it holds from enrollment. Core resolves its OWN endpoint names once at startup and refuses to
start if it cannot — distinct from, and not a relaxation of, "no DNS for targets".

### What the guarantee does and does not contain

- **Aggregate, not fair.** One bucket per namespace. A busy target can consume it; per-target
  fairness and ADR-024's 50 pps per-target ceiling remain R2a's user-space admission, which
  this ADR does not replace and does not strengthen.
- **The Go scheduler is not part of it.** Nothing in user space is on the enforcement path.
- **Only traffic from inside N.** Traffic other hosts send, and anything leaving the host by
  another namespace, are outside the invariant.

## Kernel properties relied on

Measured on Linux 6.8.0-124 (Docker bridge, veth, MTU 1500); none is a documented ABI
promise, which is why the gate re-measures them every run:

1. tc's egress hook sees every skb that leaves through `dev_queue_xmit`; only an
   `AF_PACKET` qdisc bypass avoids it, and that needs `CAP_NET_RAW` (P3).
2. `police` in packet mode charges one token per skb, while its own `packets` counter counts
   GSO segments — so the policer's counters are not a measure of the wire.
3. TCP sizes its skbs within the device's `gso_max_segs` and `gso_max_size` (P1).
4. IP fragmentation happens before the egress hook, so each fragment is its own skb.
5. UDP GSO ignores `gso_max_segs` and is segmented after the hook (hence P2's deny).

## Validation

`make safety` runs the real holder with a capability-less Scan Point stand-in in its
namespace and judges a host-side capture — never the policer's counters, which count buffers.
On the accepted tree:

- TCP at 1/5/10/20 connections (bulk writes, peer-driven ACK storms, RSTs after close): every
  window from 1 ms to 3 s within bound — worst 86/101 (1 ms), 109/110 (10 ms), 3,084/3,100
  (3 s).
- UDP_SEGMENT (three shapes), large UDP (fragments) and raw `AF_PACKET` frames from the Scan
  Point user: zero packets of a denied protocol on the wire; the raw socket is refused.
- A deliberately lowered ceiling (R=20, B=5, 100 connections) drops and fails connections —
  the bucket admits at most 65 packets in the 3 s dial timeout, so at least 35 must fail.
- A job naming Core is refused WITH the Core-target reason, and puts no packet on Core.
- The fingerprint corpus run inside the namespace identifies and evidences exactly what it
  does outside one, with zero policer drops. Two normalisations, both measured as run-to-run
  variation in unpoliced runs: the HTTP `Date:` value is masked, and the corpus's fragile
  rate-limiter fixture (10.10.0.20) is scanned but not compared.

`make safety-sabotage` breaks each precondition in turn — `gso_max_segs`, a segmentation
feature, forwarding, the catch-all drop, a UDP allow rule, `NET_RAW`, another capability, an
unpoliced interface, a widened exclusion, a missing Core refusal, and a refusal by the wrong
check — and each must fail the gate with an R2-D finding. With the UDP deny removed at the
lowered ceiling, 256 packets left in 1 ms against a bound of 5.02: the gate can see the
bypass it exists to keep closed.

## Alternatives considered

**A cost model in user space (R2-B, fixed and hybrid).** Rejected: the peer, not the engine,
decides how many kernel-originated packets a connection produces.

**Poll counters and abort (R2-C).** Rejected: it observes packets after they have left, and
its reaction time is the scheduler's. It cannot state a bound, only a hope.

**Attribute by cgroup, UID or socket.** Rejected: kernel RSTs for gone sockets carry no
owner — an nft `skuid` match saw 577 of 579 of the namespace's packets. The namespace's
egress sees all of them.

**TSO/GSO off as the whole segmentation precondition.** This was the first accepted version,
and the gate's first run disproved it (204 packets in 1 ms against 101). Kept as the record of
why P1 is what it is.

**An exception list of denied protocols.** Rejected for default-deny: an exception list
admits whatever nobody thought of.

**eBPF, per-target buckets.** Out of scope for M0.

## Consequences

- **UDP is not available to a Scan Point.** The engines are TCP-only (ADR-047), so nothing
  breaks today. Any UDP-based discovery (SNMP, DNS, IKE) needs its own safety design before it
  is enabled; it is not implicitly supported. Docker's embedded DNS answers over loopback and
  still works (the gate checks it); a deployment that needs an external resolver over UDP from
  the Scan Point fails closed at startup.
- **No raw sockets.** SYN and ARP discovery, deferred in `docs/execution-plan.md` because they
  need `CAP_NET_RAW`, are incompatible with P3 as it stands — enabling them is a change to this
  ADR, not just to an engine.
- **Deployment changes** (`deploy/INSTALL.md` §6): the holder is started first, with
  `NET_ADMIN`, the forwarding sysctls and the Core endpoints; the Scan Point joins its namespace
  with no capabilities; extra networks are connected to the holder.
- **Not yet self-checked by the Scan Point.** The Scan Point does not verify the holder's tc,
  nft or sysctl state itself; a runtime self-check is future work. Until then the guarantee
  rests on the holder's verification and on the deployment following §6.

## Review trigger

Revisit on a kernel upgrade (properties 1–5 are measured, not promised), on any request to
grant the Scan Point a capability or a non-TCP protocol, or when a segmentation path is found
that the gate does not exercise.
