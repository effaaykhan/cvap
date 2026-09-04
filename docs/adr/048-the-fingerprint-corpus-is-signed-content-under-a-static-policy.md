# ADR-048: The fingerprint corpus is signed content, under a static policy it cannot widen

**Status:** Accepted
**Date:** 2026-09-04

## Context

Week 5 is service identification. Two things a scanner needs for it are different in kind, and
the whole of this decision follows from keeping them apart.

The first is **content**: patterns that recognise a service in bytes it returned, and payloads
that provoke a response from software that will not speak first. That content needs continuous
maintenance — new products, new versions, new response shapes — which is why ADR-019 already
names the fingerprint corpus among the knowledge data that is versioned, cryptographically
signed, offline-importable, and distributed by notification-then-fetch.

The second is **what may leave a customer's network**. Session 12 put a two-probe corpus in the
scan point binary, which was right for two probes and does not survive content that changes
weekly.

The tempting move is to let the signed pack carry both. It cannot, because a signature proves
**origin, not inertness**. Nothing about signing a pack stops it carrying a probe to port 9100,
where a bare line is a print job, or to 502, where an unsolicited frame reaches a PLC's protocol
stack. If a pack could add any probe, whoever signs packs decides what packets leave every
customer's network — which is a larger authority than "content update", and not one the signing
key was issued for.

`internal/enginepolicy` is separately relevant. It is an import allowlist over
`internal/engines`, and it fired on the first build of the new engine — naming `crypto/tls` as
"a TLS client is a network client" — which is the guard working rather than an obstacle.

## Decision

### 1. The pack supplies patterns and payloads. The runtime holds a policy the pack cannot widen

`internal/scanpoint/corpus.go` loads a signed pack, verifies it, and then applies a **closed**
list of rules. Everything that fails is **dropped and reported**, never silently trimmed — the
same rule `Jobs.Tasks` takes against truncation, for the same reason: a quietly reduced corpus is
under-identification that looks like a clean run.

**The closed list. Adding to it is an amendment to this ADR, not a configuration value.**

1. **No probe to a port where unsolicited bytes are not inert.** `nonInertPorts`: 515, 631 and
   9100 (printing), 102, 502, 20000, 44818 and 47808 (industrial and building control).
2. **No probe payload larger than `MaxProbePayload`** (512 bytes), measured against the
   **substituted** size. A probe is a protocol greeting; a large payload is how a probe becomes
   something else. Substitution of `{{target}}` happens in the engine, after every check in the
   runtime, so bounding the authored bytes bounds the wrong thing: an audit drove a 510-byte
   probe of 51 placeholders through the policy and captured 867 bytes on the wire against a
   v4-mapped address, ~1989 against a full IPv6 one.
3. **No probes at all in safe mode.** Enforced in `job.budget` by handing over an empty list.
4. **No probes at all for a fragile target.** Likewise.

Rules 3 and 4 live in `job.budget` rather than in the pack filter because they are decisions
about a **job**; 1 and 2 are decisions about a **pack**.

Three further checks are in the same file and are deliberately **not** part of the safety list,
because they bound this runtime rather than a target: `MaxPackProbes` (2000), the rejection of a
probe that sends nothing at all, and the rejection of a port outside 1..65535. That last one is
inert today — the engine's process shell drops an out-of-range port rather than truncating it —
and it is refused anyway, because the safety of a denylist that compares numbers must not rest on
a narrowing conversion two processes away behaving one way rather than the other. 74636 truncates
to 9100.

**There is no environment variable, pack field or policy row that reaches any of these.** A
policy a deployment can widen is not a policy: the argument for letting a signed pack supply
probes rests entirely on the runtime holding a limit the pack cannot move, and a
`CVAP_SP_ALLOW_...` escape hatch would hand that authority to whoever writes the deployment
manifest.

The built-in corpus is run through the same filter **at load**, by `BuiltinCorpus`, and not only
in a test. The policy was written for content that arrives signed, which left the in-binary half
exempt by construction — exactly the gap where a probe to 9100 would sit unnoticed.

That filter has now caught two of this ADR's own draft rules being wrong. The first refused any
probe with no payload, which `tls-hello` violates deliberately: it handshakes and sends no
application data, and the certificate is what it is buying. The second refused a probe carrying
no match rules as pure packet spend — true of a probe read in isolation and false of this engine,
because `runProbe` falls back to the job's banner rules, which is exactly what the `newline`
probe depends on. Both were proposed reasonably; running the built-ins through the policy is what
said they were wrong.

### 2. `make safety` measures the policy at the wire, not only in a unit test

Three phases now run under egress capture: discovery under a safe job, the fingerprint engine
under an **intrusive** job with the real built-in corpus, and the fingerprint engine again under
a **safe** job. The gate asserts, in addition to what it asserted before:

- **Not one payload byte reaches a non-inert port.** Lab target `10.10.0.40` listens on 9100 and
  631 for this: against a closed port the assertion passes trivially, because a refused
  connection cannot carry a payload whether the denylist works or not. Both ports are in the
  phase's port list — an audit found only 9100 was, which is half a wire assertion.
- **A safe job puts no payload on the wire at all.** ADR-021's central claim, measured where it
  is actually about.
- **The intrusive phase completed at least one TLS handshake.** Added because the gate printed
  "the TLS handshake is inside the capture" while completing none: the corpus reaching it had no
  TLS probe, so `TLSHandshakeCost` was asserted by nothing and the wire-to-charged ratio was
  honest about a workload nobody cared about. A gate that cannot tell it did nothing is the
  failure this file exists against.

Both were sabotage-tested: removing 9100 from the denylist produces `2 payload byte(s) reached a
NON-INERT port`, and handing the safe phase a probe list produces `a SAFE job put 348 payload
byte(s) on the wire`.

The gate reads the corpus from `test/safety/corpusdump`, which asks `scanpoint.BuiltinCorpus`. A
probe list restated inside the gate would drift from the shipped one and the gate would go on
reporting a clean run about a corpus nobody uses.

### 3. Fetch is deferred; offline import is not

Implemented this session: the pack format, ed25519 signature verification, loading a local signed
file, the static policy, and `RulePackStatus` reported to Core on every connect.

Deferred: `RulePacks.FetchRulePack` and the `RulePackUpdate` notification. **The named unblocker
is signing-key custody and rotation.** Every fetch path needs a scan point to decide which key to
verify against — `RulePackChunk.signing_key_id` exists for exactly that — and there is nowhere to
put a key set or a rotation policy today. Fetch without it means either one hard-coded key
forever, or a scan point that cannot survive a rotation. Offline import needs none of that, and
ADR-019 calls it required rather than optional.

Also deferred: **persisting** `RulePackStatus`. Core logs it, at warn for anything that is not
`LOADED`. That meets "the refusal is not silent" and no more — it cannot be queried, alerted on,
or shown beside the scan whose coverage it explains. Storing it needs a table and a migration,
and the fetch half needs them too, so the two land together.

### 4. A refused pack is not fatal

The scan point runs on its built-in corpus and reports `REJECTED_SIGNATURE` or
`REJECTED_FORMAT`. Refusing to start would turn a content problem into an outage, and a scan
point that is offline identifies nothing at all — strictly worse than one on the built-ins.
ADR-019's requirement is that the refusal is not **silent**, not that it stops the process.

A pack path configured without a key path **is** fatal, at startup. A pack with no key to check
it is an unsigned pack.

### 5. TLS lives inside the `service` payload, under a `tls` object

**Not its own observation type, and this is the part most likely to be "normalised" later.**

A certificate is a property of a service on a port. Week 6's non-CVE rules ask questions like
"does this HTTPS service present an expired certificate" and "is this key below 2048 bits", and
with TLS as a separate observation type every one of those becomes a join between two
observations keyed on an address and a port number — across a monthly-partitioned table that is
the largest in the system (ADR-016).

The `tls` object carries the negotiated version, the cipher suite, ALPN, and a bounded chain
description: subject, issuer, serial, validity, SANs, self-signed-by-name, CA flag, signature and
public-key algorithms, key size, extension count.

**Do not split this into its own observation type without reworking the week 6 rules that read
it.**

### 6. The engine holds a second copy of the three send-side controls

Scope stays at Core and the runtime (ADR-027) and this does not change that. But an audit drove a
hand-written job into the engine's stdin — bypassing the runtime entirely, marked safe and
fragile, carrying a probe for 9100 — and captured `@PJL INFO ID` arriving there. The engine
already compiles in ADR-024's rate, concurrency, timeout and chain ceilings on the argument that
"a ceiling that arrives over the same channel as the value it bounds is not a ceiling"; the three
controls with the **largest** blast radius arrived over exactly that channel and were duplicated
nowhere, while `enginewire.Probe`'s own comment claimed a probe was "subject to every rule".

So the engine now also withholds: no probes unless the mode is intrusive, none for a target
marked fragile, none to a port on its own compiled-in copy of the denylist, and none whose
substituted payload exceeds the bound. `grep Fragile` in that package previously returned a
struct field and no reader — the same defect a packet-capture audit found in the discovery
engine, repeated.

**This is not a third scope site.** Scope asks WHICH HOST, needs data an engine must never hold,
and stays where ADR-024 puts it. These ask WHAT MAY BE SENT, and they are answered from constants
compiled into the binary that no wire field can move. The two denylists are asserted equal by a
test that reads both source files, because a second site that quietly permits what the first
refuses is worse than no second site at all.

### 7. `internal/engines/fingerprint` may import `crypto/tls`, `crypto/x509`, `crypto/rsa` and
`crypto/ecdsa`, and `net`

`net` for the same reason ADR-047 grants it to discovery: identifying a service means connecting
to it.

The crypto imports are the new argument:

- `crypto/tls` — a handshake is a conversation and no fixed byte string performs one. Without it
  the certificate is unreachable and week 6's rules have no evidence to run on.
- `crypto/x509` — the certificate type. `crypto/tls` has already parsed the chain by the time
  this engine sees it.
- `crypto/rsa`, `crypto/ecdsa` — key size, which is a finding. Both are pure arithmetic.

Three further imports — `crypto/rand`, `crypto/elliptic`, `crypto/x509/pkix` — are **test-only**,
for building a certificate the tests inspect. They are listed in the exceptions map rather than
waved through because the guard checks test imports on purpose: "only in tests" is how the first
exception gets made without anyone deciding to make one. The alternative was a committed PEM
fixture, which means a private key in the repository.

Deliberately **not** granted: `net/http` (a redirect-following client constructs its own
targets), `os`, `os/exec`, `syscall`.

### 8. `InsecureSkipVerify` appears exactly once, in a constructor named for the argument

A verifying dial **fails on exactly the certificates worth reporting** — expired, self-signed,
wrong hostname — and returns an error where the evidence should be. Verification is therefore off
here and nowhere else in this codebase.

That is a dangerous combination, because the words are identical to the ones in every real
vulnerability. Three things hold it:

1. `inspectOnlyTLSConfig` is the only place it appears; no bare `tls.Config` exists at a call
   site in this package.
2. A **mutation** flips it to `false` and requires the tests to fail. That is what makes the
   deliberateness load-bearing rather than incidental: without it, someone "fixing" the alarming
   line would silently lose coverage against every self-signed certificate in an estate, and
   nothing would break loudly.
3. `TestAVerifyingDialCannotSeeTheCertificateAtAll` asserts the premise directly — a verifying
   client gets an error where this engine gets a chain.

`MinVersion` is `tls.VersionTLS10` for the same reason: a client that refuses to speak an
obsolete version cannot report a server that only offers one. A mutation raises it and requires a
failure, which needed a TLS-1.2-only test server — against a modern server the floor is
unexercised and the mutation survived.

**Certificates from a scanned host are attacker-controlled by definition.** `MaxChainDepth` (6),
`MaxSANs` (64) and `MaxNameLength` (512) bound what one can make this engine hold and forward.
Each has a mutation. Truncation is always reported alongside the untruncated **count**, so the
fact survives the data.

`MaxExtensionsFlagged` (128) bounds **nothing**, and an earlier draft of this ADR claiming it
"bounds the extension walk" described a walk that does not exist: `crypto/x509` has already
parsed the extensions, this code copies none of them into the payload, and what it records is
the count plus a flag saying the count is unusual. Measured against 700 DNS and 700 IP SANs, 204
extensions, a 2,000-character DN and a three-certificate chain, the whole observation payload is
6,416 bytes.

### 9. An OS hint is never authoritative, mechanically

`osHint` has no `authoritative` field. Its `MarshalJSON` writes the literal `false`.

There is therefore no assignment anywhere — present or future — that can make an OS hint claim
authority; Phase 3's real OS detection has to change that method, which is a diff a reviewer sees
and an ADR can be asked for. A comment saying "do not treat this as OS detection" is a hope.

This matters because ADR-014 makes OS attribution decide **which vendor advisory feed a host is
matched against**. An OpenSSH banner ending `Ubuntu-3ubuntu0.4` is genuinely good evidence and it
is still a string the host chose to send; a wrong feed at high confidence produces confident
findings that are wrong in both directions and poisons the knowledge plane rather than merely one
scan.

### 10. Softmatch is a terminal outcome, and a hard match outranks it regardless of confidence

"This is HTTP, product unknown" is a correct answer. `Softmatch` is derived from the **resolved**
product rather than copied from the rule that fired, so the generic `Server: (?P<product>…)`
rule — whose static `Product` field is empty — is not reported as soft while holding a product.
A rule declaring itself soft while naming a product is refused by the pack policy.

Ranking soft against hard by confidence alone was a defect a test caught: `server_tokens off`
yields a soft "it speaks HTTP" at 0.70, and the shape rule that recovers `nginx` from an error
page carries 0.60 deliberately, because shape evidence is weaker than a self-description. On
confidence alone the vaguer answer won and the shape probe's whole reason to exist was discarded
after being paid for in packets. The two numbers are not on one scale: confidence ranks belief
**within** a kind of answer, and soft against hard is a difference in kind.

A **hard** match ends the probe chain. A **soft** one does not — the product is what the later,
rarer probes exist to recover. What bounds the cost is `PlatformMaxProbesPerPort` (8) and rarity
ordering, with port-specific probes ahead of generic ones.

### 11. Banner rules travel in every mode; probes do not

Reading is not sending. The bytes have already arrived by the time a rule looks at them, so
withholding banner rules under a safe job would cost identification and buy no safety at all. The
asymmetry between those two lines in `job.budget` **is** the safe/intrusive distinction.

## Consequences

**Safe mode identifies seven of the nine services in the week 5 brief, and this was measured
rather than assumed.** SSH, SMTP, FTP, POP3, IMAP, Telnet and MySQL announce themselves.
**PostgreSQL and MSSQL do not** — a connect to PostgreSQL returns nothing for three seconds,
because the protocol has the client speak first. Both are in the probe corpus instead, so they
are identified under an intrusive job and not under a safe one.

**SNMP is deferred with a named unblocker: UDP.** SNMP is UDP-only in practice, discovery finds
TCP ports only (ADR-047 deferred every non-TCP method), and service identification runs against
ports discovery found. There is no UDP port to identify until there is UDP discovery. DNS is in
the corpus over TCP/53.

**Four probes have never fired against a live server**: SMB, RDP, MSSQL and DNS. The lab has no
target for any of them, which is a gap in the **lab**, recorded in `probes.go` rather than in a
commit message. Their payloads are the standard opening packet of each protocol, sent before any
authentication, and they are bound by the static policy regardless of whether their patterns turn
out to match. The HTTP, HTTPS, response-shape and PostgreSQL rules were written from captured
responses.

**Negotiated TLS version is the best both ends support, not the worst the server accepts.** A
server offering TLS 1.0 and 1.3 reports 1.3. Detecting an obsolete floor needs one handshake per
version — a packet cost per port — and is deferred.

**The fingerprint engine re-connects to ports discovery already found.** `ToEngine.Ports` exists
on the wire and **nothing fills it** — not Core, and not the runtime either; an earlier draft of
this ADR claimed the runtime supplied it, which an audit found untrue. Planning a fingerprint job
from discovery's observations is week 5's second half, and until then the engine falls back to
`ServicePorts()`. The cost is a duplicated connect per port, which is exactly the kind of
silently-doubled packet spend the budget exists to make visible.

**`internal/engines/enginerate` is now shared.** The packet-accounting model moved out of the
discovery engine because a second engine that sends packets makes it shared or duplicated, and
duplicated is not an option: `make safety` asserts a wire-to-charged ratio against **one** model,
and two copies means the gate binds whichever the test happens to exercise while the other
drifts. The three numbers it took a packet capture to get right — a sub-second burst, the SYN
retransmit train, three packets beyond the SYN — are exactly the kind that get copied wrong.

**A TLS handshake costs `TLSHandshakeCost` (4) beyond the TCP connection**, and the number is
measured rather than counted off the record diagram. Three was the first value; a capture of nine
TLS probe connections put 76 packets on the wire against 68 charged, a shortfall of close to one
per connection — the ACK of the server's flight. At four the model errs high, which is the
direction a ceiling must lean, and `make safety` reports 1.00 across the three phases.

**The rate budget now charges every packet, not only the SYN.** An audit measured the bucket
debiting `SynCost` before a dial while the handshake, the ACK/FIN pair and the payload were
reported to the reclaim path and paced nothing: 112 packets in a one-second window against
ADR-024's 50 pps ceiling, 2.24x — while the gate's wire-to-charged ratio read 1.01, because that
ratio compares the wire against the **reported** count and never against the tokens taken.

The repair took three attempts and only the third worked, each measured:

1. Settle after the fact — 65 in the worst second. The packets are gone by the time the tokens
   are taken, so a job short enough to finish before the debt is paid never pays it.
2. Charge each phase just before it sends — 63, and no better for a reason only a capture showed:
   a connection waiting on tokens for its handshake sits **idle**, and idle connections produce
   retransmits and teardowns nobody charged for.
3. Acquire the whole probe's expected cost **before the dial**, then settle. 54 in the worst
   second against a designed maximum of 55 — the 50 ceiling plus the bucket's burst of 5 — and a
   9.88 pps mean against a 10 pps fragile budget.

`Settle` also **refunds**: a refused connection costs one packet against a `SynCost` of three, and
a bucket that kept the difference would run a scan of mostly-closed ports at a third of the rate
its operator asked for.

**A fragile target is now serialised as well as slowed** — `PlatformFragileMaxConcurrent` is 1.
At 10 pps the mean was honest and the worst second was 18, because the packets of one
TCP-plus-TLS exchange are atomic and two exchanges landing together is the peak. Connection count
is the other lever ADR-024 control 3 is about, and `internal/dispatch` already records why: a
host answering 20 simultaneous connects at 5 pps is under more pressure than one answering a
single connection at 50 pps.

**The lab gained four targets and one fix.** A TLS host with an inspectable certificate
(10.10.0.15), an nginx with `server_tokens off` (10.10.0.16), a listener on the non-inert ports
(10.10.0.40), and `LISTEN_PORT=22` on the SSH host — which had been listening on 2222 for three
sessions, a port no scan list contains, so the lab's only banner-volunteering target had never
been reachable and "the safe/intrusive distinction is testable against the lab" was a comment
rather than a fact. Found by connecting to it.

## Alternatives considered

**Let the signed pack carry the whole policy.** Rejected: a signature proves origin, not
inertness. This makes whoever signs packs the decider of what packets leave every customer's
network.

**Make the denylist configurable so a deployment can scan its own printers.** Rejected, and this
is the one worth naming because it will be asked for. A deployment that can widen the policy is a
deployment where the policy is advisory, and the request always arrives as a reasonable special
case. If printing ports must be probed, that is an amendment here with an argument attached, not
a row in a table.

**Refuse to start on a bad pack.** Rejected: it converts a content problem into an outage, and a
scan point that is offline identifies nothing at all.

**A separate `tls` observation type.** Rejected: see §5. It makes every week 6 certificate rule a
join across the largest table in the system.

**Fingerprinting inside the discovery engine.** Rejected: it would hand `crypto/tls` to the
engine that sweeps every port of every host, widening the most exposed exception in the tree for
a capability it does not need. The cost of a separate engine is the duplicated connect above,
which is visible in the packet budget rather than hidden.

**A comment saying an OS hint is not authoritative.** Rejected: see §9.
