---
name: fingerprint-engine-wire-findings
description: Packet-capture findings against internal/engines/fingerprint (ADR-048, session 13) — token bucket undercharges by 2x on the TLS path, MaxProbePayload beaten by {{target}} substitution, engine holds no denylist/fragile/safe check, and make safety measures zero TLS handshakes. Re-test these first on any fingerprint or enginerate diff.
metadata:
  type: project
---

The fingerprint engine landed 2026-09-04 (`internal/engines/fingerprint`,
`cmd/cvap-engine-fingerprint`, `internal/scanpoint/corpus.go`, `internal/scanpoint/banners.go`,
`internal/engines/enginerate`). Second engine that can send packets, first that can speak TLS.
Everything below was measured with tcpdump on `cvap-lab_segment-a` (or loopback, which is in
`lab/scope.txt`), not read.

## Open, reproduced 2026-09-04

- **The token bucket is debited `SynCost` only; `EstablishedCost` and `TLSHandshakeCost` are
  counted but never charged.** `identifyTarget`/`identifyPort` call
  `limiter.TakeN(ctx, enginerate.SynCost(timeout))` and then `count(cost)` for 4 (TCP) or 7
  (TLS) packets. Per TLS-probed open port: **6 tokens taken, 11–12 packets on the wire.**
  Measured at the ADR-024 default of 50 pps per target: **112 outbound packets in a single
  1-second window** (mean 53 pps, 480 packets / 9.03 s), 40 TLS probes at 10.10.0.15:443.
  At a policy-lowered 10 pps: 34 packets in one second. Discovery has the same shape
  (1.33x); the fingerprint engine's two connections per port plus the handshake make it 2x.
  **`make safety` cannot see this**: it compares the wire against the engine's REPORTED
  count (which does include those costs), not against the tokens the bucket took. It
  reports 1.01 while the bucket is being exceeded by 2.2x.
- **`MaxProbePayload` (512) is checked before `{{target}}` substitution.** A pack probe of
  51 × `{{target}}` = 510 bytes passes `applyProbePolicy` and puts **867 payload bytes** on
  the wire against a v4-mapped target (`::ffff:10.10.0.11`, 17 chars); a full IPv6 target
  (39 chars) gives ~1989. Substitution happens in `fingerprint.substituteTarget`, after
  every bound.
- **A TLS probe declares a 0-byte payload and sends ~1547.** The measured ClientHello is
  **1483 bytes** (Go's post-quantum keyshare) plus a 64-byte Finished. Policy rule 2 is
  about `Payload` only, and rule "a probe that sends nothing" explicitly exempts TLS
  probes. So the payload bound does not cover the handshake at all.
- **The engine holds no non-inert denylist, no fragile check and no safe-mode check.** A
  hand-written job with `"safety_mode":"safe"`, `"fragile":true` and a probe on 9100 put
  **14 bytes of `@PJL INFO ID\r\n` on 10.10.0.40:9100 and 2 bytes on 631**. The runtime
  (`corpus.go` + `job.budget` + `engineHost.start`) is the ONLY site. The engine duplicates
  rate, concurrency, connect timeout and `MaxProbesPerPort` as compiled-in ceilings — with
  a comment saying duplication is deliberate — and does not duplicate the three controls
  that decide whether a payload leaves at all.
- **`Target.Fragile` reaches the engine and is read by nothing.** Same as discovery. `grep
  Fragile internal/engines/fingerprint` returns one struct field and no reader.
- **`Solicited` is false on observations for hosts the engine provoked.** Set only inside
  the `ok` branch of a probe result, so: a HEAD request whose response matched no rule
  (10.10.0.11:80, evidence is an HTTP response, `solicited:false`); a completed TLS
  handshake with no application match (10.10.0.15:443, `method:"tls"`, `solicited:false`);
  and a `\r\n` sent to 631 that returned nothing (`method:"none"`, `solicited:false`,
  confidence 1.0, payload text "we looked and found nothing"). `payload.go` says Solicited
  answers the operator question "did we touch this host".
- **Per-TARGET rate is not aggregated across concurrent jobs.** `allocator` divides the
  1000 pps per-scan-point ceiling only. Two concurrent jobs, same fragile target, each
  budgeted 10 pps: **18 packets in one second** at a 10 pps ceiling, linear in job count.
  Now concretely reachable because discovery and fingerprint jobs cover the same host —
  ADR-048 says so itself ("re-connects to ports discovery already found").
- **`ToEngine.Ports` is never populated by the runtime.** `engineBudget` has no Ports field
  and `engineHost.start` does not set it, so every fingerprint job falls back to
  `ServicePorts()` — 50 ports including **631**. ADR-048 says "`ToEngine.Ports` exists and
  the runtime supplies it; Core does not yet fill it". Both halves are missing.
- **The safety gate never scans 631.** `FINGERPRINT_PORTS = [22, 80, 443, 5432, 9100]`
  while `NON_INERT_PORTS = {"9100", "631"}`. Half the wire assertion is unexercised.
- **`internal/enginewire` is still outside the import guard's roots** (roots are
  `internal/engines` and `cmd/cvap-engine*`), and it has grown a lot this session.

## ADR-048 claims that are NOT true of the code (checked 2026-09-04)

- **`make safety` measures no TLS handshake.** `internal/scanpoint/probes.go` was not
  changed this session: `ProbeCorpus()` still returns exactly `http-head` and `newline`,
  neither with `TLS: true`. Measured in the gate's own intrusive capture: 10.10.0.15:443
  received SYN/ACK/FIN/ACK and **0 payload-bearing packets**, and the observation is
  `{"method":"none"}` with no `tls` object. So "a TLS handshake costs TLSHandshakeCost (3)
  … make safety measures whether it holds, and reports 1.01" is false, as is the gate's
  success message "the probe payloads and the TLS handshake are inside the capture".
  The whole TLS capability is unreachable from the shipped corpus.
- There is **no `tls-hello` probe**, no PostgreSQL/MSSQL/SMB/RDP/DNS probe, and **no HTTP
  banner rule at all** in `banners.go`. ADR-048's §1 anecdote about `tls-hello`, its
  consequence "PostgreSQL and MSSQL … are in the probe corpus instead", "Four probes have
  never fired against a live server", and §9's `server_tokens off` soft-0.70 / shape-0.60
  ranking argument all describe content that is not in the tree. Measured: 10.10.0.16 (the
  `server_tokens off` target added for that argument) yields no service at all, and
  10.10.0.11:80 returns an nginx `Server:` header no rule reads.
- **`MaxExtensionsCounted` bounds nothing.** `describeCert` does `ExtensionCount =
  len(c.Extensions)` and sets a boolean; there is no walk to stop.
- **ALPN can never be populated.** `inspectOnlyTLSConfig` sets no `NextProtos`; measured
  `alpn=[]` in the ClientHello a hostile server received.
- `test/safety/corpusdump` says it prints "the probe list after the static safety policy" —
  `BuiltinCorpus()` never goes through `applyProbePolicy` (only
  `TestTheBuiltinCorpusObeysItsOwnPolicy` does).

## Measured and CORRECT — do not re-report

- **No SNI, no ALPN, no DNS, no second destination.** A hostile server logging
  `ClientHelloInfo` saw `sni="" alpn=[]`; `supported_versions=[772 771 770 769]` confirms
  the TLS 1.0 floor is offered deliberately. Captures show one destination and zero UDP/53.
- **The certificate bounds hold.** Against a cert with 700 DNS + 700 IP SANs, 204
  extensions, 2000-char DN and a 3-cert chain: subject/issuer truncated at 512, 64 DNS and
  64 IP names with `names_truncated:true`, `extension_count:204` with
  `extensions_truncated:true`, observation payload **6416 bytes**. Go's own 64 KB handshake
  limit caps the input above that.
- **The pack policy refuses a probe to a non-inert port**, by name, loudly: a signed pack
  with probes on 9100 and a TLS probe on 631 lost exactly those two and loaded the rest.
- **`max_concurrent_per_target` binds exactly at the wire** (20 -> 20 simultaneous
  connections, counted SYN..first FIN/RST).
- **Cancellation is prompt.** No signal handler and no in-band cancel; SIGTERM's default
  disposition terminated the process in **5 ms** with no further ClientHello at the server.
  Well inside ADR-024's 10 s. The cost is that unwritten observations are lost.
- **`ErrProbesUnderSafeMode`** is checked in `engineHost.start` before the process exists.
- **`isException` matches exactly**, so `crypto/x509` does not grant `crypto/x509/pkix`.
- **`lab-scope-guard.py` now matches `cvap-engine-\w+`**, so the fingerprint binary is
  covered.

## Harness, so the next audit does not rebuild it

`cvap-safety-capture:local` (built by `make safety`) has tcpdump. Drive the engine with:
`docker run --rm --network cvap-lab_segment-a --cap-add=NET_RAW -v <work>:/w
cvap-safety-capture:local /w/run.sh cvap-engine-fingerprint <phase>` where run.sh starts
tcpdump, sleeps 2, then feeds `/w/job-<phase>.json` on stdin. Repeating a port in
`"ports"` is the cheapest way to force N connections to one listener. The container's
busybox `date` has no `%N`, so time SIGTERM on the host instead. `127.0.0.0/8` is in
`lab/scope.txt`, so a hostile TLS server on loopback is a legal target and needs no
container. A `tls.Config.GetConfigForClient` hook is the direct way to read what SNI/ALPN
the engine actually offered.

Related: [[discovery-engine-wire-findings]], [[scanpoint-runtime-bypasses]].
