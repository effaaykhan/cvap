---
name: discovery-engine-wire-findings
description: Packet-capture findings against internal/engines/discovery (ADR-047, commit 9d982b5) — token re-banking, fabricated liveness, hostname resolution, unsuppressed probes on fragile. Re-test these first on any engine diff.
metadata:
  type: project
---

The discovery engine landed 2026-09-04 (`internal/engines/discovery`,
`cmd/cvap-engine-discovery`, `.github/scripts/safety_gate.py`, `test/safety/run.sh`,
`lab/targets/slow`). First code in the repo that can put a packet on a wire. Everything
below was measured with tcpdump in a container on `cvap-lab_segment-a`, not read.

## Open, reproduced 2026-09-04

- **The token bucket re-banks a full burst after any idle period.** `newBucket` fixed the
  t=0 burst (`tokens: 1`) but `capacity` is still the whole allocation, so any stall of
  `capacity/rate` seconds restores it. `probeAlive` stalls one connect-timeout per silent
  discovery port, so this is the normal path, not an edge. Measured: **10 connects within
  1 ms at a configured 10 pps fragile cap**, twice, identical. `backOff()` halves `rate`
  and leaves `capacity`, so an adaptively-slowed scan re-banks the ORIGINAL ceiling.
- **`probeAlive` reports any non-timeout dial error as `alive: true` at confidence 1.0.**
  ENETUNREACH, a DNS ServFail and a malformed target all become
  `method: "tcp-refused:80"`. Measured: three targets, **zero outbound packets in the
  capture**, three live hosts claimed, `ports_scanned` claiming coverage, and a `sent`
  count of 9 packets never sent.
- **A hostname target is resolved by the engine and nothing re-checks the answer.**
  `scope.Permits` allows `KindHostname` on string equality; `internal/scope` says outright
  that a hostname rule does not cover the address it resolves to. Reproduced: allow
  `printer.corp.example` + exclude `10.10.0.20` -> permitted at both sites -> 10 TCP
  packets at the excluded host.
- **`fragile` does not suppress probes.** `Target.Fragile` reaches the engine and is read
  by nothing (`cmd/cvap-engine-discovery/main.go` assigns it; no reader anywhere).
  `job.budget()` lowers rate only. Measured: 92 bytes of probe payload at a fragile
  target, including `\r\n` to 631. The `newline` probe has no `Ports`, so it goes to every
  open port — 631, 9100, 502 are printer/SCADA ports where a bare line is not inert.
- **Rate is denominated in connect attempts, not packets.** `count(1)` per dial; the
  kernel sends 3 SYNs per timed-out connect. Measured ratio 2.05–2.94 outbound packets per
  budgeted "packet" against a filtered host — the fragile case.
- **The safety gate cannot see DNS.** `test/safety/run.sh` captures with filter `'tcp'`
  while `safety_gate.py`'s docstring claims it covers "a DNS lookup to a resolver".
  Measured: same scan, no filter = a dozen UDP/53 queries; filter `tcp` = zero.
- **A killed job records nothing about what it touched.** Only OPEN ports emit; coverage
  lives in the host row emitted last. Measured: 9 s of scanning, 73 packets,
  `observations.jsonl` = 0 bytes after SIGTERM and after SIGKILL.
- **Chunking multiplies the missing aggregate.** `dispatch.TasksPerJob = 32` turns a /24
  into 8 claimable jobs; `maxJobsPerPoll = 5` with no total cap. Measured: 5 concurrent
  engines from one container = **262 pps** aggregate, linear, nothing subtracting.
- **`lab-scope-guard.py` does not list `cvap-engine-discovery`.** `/tmp/eng --targets
  <public ip>` returns rc=0. `cvap-scanpoint`, which cannot itself send a scan packet, is
  blocked.

## Measured and CORRECT — do not re-report as findings

- Safe mode sends **zero payload bytes**. 33 outbound packets, 3 targets, 0 B.
- Intrusive sends exactly the handed probe and nothing more (87–88 B HEAD, 2 B newline).
- `max_concurrent_per_target` binds exactly at the wire (4 -> 4, 20 -> 20).
- SIGTERM and SIGKILL: **zero** outbound packets after the signal returns.
- The engine has no `net/http` and no URL parsing, so a redirect cannot be followed.
- The fragile cap does produce the claimed difference when the bucket is not pre-banked:
  6 banners at 10 pps, 0 at 500 pps.

## Harness, so the next audit does not rebuild it

`docker run alpine:latest sh -c 'apk add --no-cache tcpdump iptables bind-tools'` then
`docker commit` — Docker Hub auth is broken here, only cached images work, and the lab
networks are `internal: true` so a container on them can install nothing.
`tcpdump -i any` gives LINUX_SLL2: direction is the token before `IP`, and **loopback
traffic is labelled `In`**, so any egress filter keyed on `Out` silently drops DNS.
To simulate a filtered host without touching the lab, drop the REPLIES in the scanner
container's INPUT chain (`iptables -A INPUT -p tcp --tcp-flags RST RST -s <target> -j
DROP`); dropping in OUTPUT hides the packet from tcpdump as well.
Related: [[scanpoint-runtime-bypasses]], [[lab-scope-guard-bypasses]].
