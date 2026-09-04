# ADR-049: Probes have kinds, and a key exchange is not a payload

**Status:** Accepted
**Date:** 2026-09-04
**Supersedes:** ADR-048 §1 rule 2 and the closed-list framing around it. Everything else in
ADR-048 stands.

## Context

Week 5's second half is asset identity resolution, and it ran into a wall in ADR-007's own key
table.

ADR-007 ranks identity keys: strong (agent UUID, cloud ID, DMI UUID, TPM or host certificate),
moderate (SSH host key, service certificate, hostname+domain+OS), weak (MAC, NetBIOS, IP within
a window). A merge needs one strong key or corroborating agreement among weaker ones, and **IP
alone never merges**.

Measured against what this platform can actually produce, that table is mostly out of reach.
Every strong key needs an agent or cloud metadata, both out of MVP scope. `mac` needs ARP, which
needs a raw socket (deferred, ADR-047). `netbios` needs an SMB name query the corpus has no probe
for. `hostname_domain_os` would have to be built from a hostname the target chose and an OS hint
ADR-048 §9 explicitly marks non-authoritative.

That leaves `service_cert_fp` and `ip_window` — and the certificate fingerprint **was not being
emitted at all**. `certPayload` carried subject, issuer, serial, validity, SANs and key size, and
no hash. So the only key a scan produced was the one ADR-007 says never merges, and week 5's
deliverable — scan the lab twice with a DHCP change in between and get one asset — was
unreachable for want of a SHA-256.

The remaining moderate key is the SSH host key, which most Linux hosts can offer and nothing else
can. Getting it means performing a key exchange. That is where ADR-048 stopped fitting.

## Decision

### 1. A probe has a KIND, and only a payload probe is bounded like a payload

ADR-048's static policy is four rules: no probe to a port where bytes are not inert, no payload
over `MaxProbePayload`, none in safe mode, none at a fragile target. Three of those are about
whether a probe may run at all and apply to anything. **The second is about bytes**, and it was
written when every probe was a byte string.

An SSH key exchange has no payload. It has a conversation. Stretching a bound written about a
payload over a handshake would have been the wrong repair — the number would have meant nothing
and the policy would have looked like it covered something it did not.

So `enginewire.Probe.Kind` is explicit:

- `""` — a payload probe. Sends bytes, reads a bounded reply. `MaxProbePayload` applies.
- `"ssh_hostkey"` — a key exchange, described below.

`TLS` stays a separate boolean because it is a **transport modifier**, not a kind: an HTTPS probe
is a payload probe wrapped in a handshake. The two fields answer different questions.

**The kind set is closed and amendment-gated**, exactly as the non-inert port denylist is. A kind
this build does not implement is REFUSED by the runtime's static policy and dropped by the engine
— not ignored, and not fallen through to the payload path, where it would send nothing and look
like a probe that found nothing rather than one that never ran. Adding a kind is an amendment to
this ADR.

### 2. The SSH host-key kind: what it offers, and where it stops

**KEX algorithms offered: `curve25519-sha256` and its libssh.org alias, and nothing else.** A
server that speaks neither ends the exchange with no host key learned, which is the correct
outcome. Widening the offer means implementing more of the protocol, and the point is to
implement as little as possible.

**Host key algorithms offered: broadly**, because the server picks one and what it picks is the
evidence — `ssh-rsa` still on a server's list is a week 6 finding.

**No authentication is attempted, ever. The exchange is abandoned once the host key arrives.**

That last clause is the safety property, and it is **structural rather than promised**. The
engine sends a version string, a KEXINIT and a KEX_ECDH_INIT; it reads a KEXINIT and a
KEX_ECDH_REPLY; it takes the host key out of the reply and closes the socket. Past that point the
protocol is **not implemented**: no `SSH_MSG_NEWKEYS`, no key derivation, no service request, no
userauth. The shared secret is never computed — the ephemeral X25519 key exists because the
protocol requires the client to send one and its private half is used for nothing.

Invariant 9 is that detection establishes evidence without achieving impact, and an SSH probe
that proceeded past the key exchange would be touching authentication.

Two tests hold it. `ssh_test.go` runs a server that records every message the client sends and
asserts it sent exactly KEXINIT and KEX_ECDH_INIT and then zero further bytes. A second test in
`internal/scanpoint` parses `ssh.go` and fails on any identifier or string literal naming a
message past the exchange — parsed rather than grepped, so the file's comments about what it
deliberately omits do not count as implementing them.

### 3. `golang.org/x/crypto/ssh` is refused, and that is the whole argument for §2

That package reads a host key in about six lines, through a `HostKeyCallback` that captures the
key and returns an error to abort. It would have been a smaller diff by two hundred lines.

It is also a complete SSH client: it can authenticate. Importing it would put a package capable
of sending credentials inside the engine that scans strangers' networks, and the guarantee would
degrade from "there is no code here that can" to "we call it in a way that doesn't". The first is
a property; the second is a convention, and this codebase has a long record of conventions being
true right up until the session that made them false.

The cost is ~200 lines of binary protocol. The benefit is that invariant 9 holds by construction.

### 4. Identity probes run past a hard match; identification probes do not

ADR-048 §10 stops the probe chain at a hard match, because buying more names after the product is
known is waste.

Measured against the lab's OpenSSH host, that rule threw away the thing this session exists to
collect: the banner names OpenSSH and its version, so the chain ended, and the host-key probe
never ran. The service was perfectly identified and the asset could not be merged across a DHCP
change.

They are different questions. *What is this?* is answered by a name, and more names are waste.
*Which host is this?* is answered by a fingerprint, and no amount of naming produces one.

So a probe that yields an identity key runs even when the service is already identified. That set
is **derived, not declared**: an SSH host-key probe or a TLS probe, both of which produce a
fingerprint the engine computes itself. A pack cannot invent a third without a new kind, which is
amendment-gated — which is tighter than a boolean any pack could set to exempt its probe from the
chain's economy. `MaxProbesPerPort` still bounds the total, so this changes which probes are
inside the cap, not how many.

### 5. The corroboration rule, and what "independent" means

ADR-007 says a merge needs "one strong key, or corroborating agreement among weaker ones" and
does not say how many. `internal/domain/identity.go` is where that becomes a number:

| Evidence | Decision |
|---|---|
| one strong key agrees | merge |
| two **independent** moderate keys agree | merge |
| one moderate agrees, one weak corroborates, none disagree | merge |
| weak alone | never merges |
| disagreement at equal-or-higher strength | queue |
| more than one candidate qualifies | queue |

**Two moderate keys are independent when they come from different services on the asset.** An SSH
host key and a TLS certificate are two facts. Two TLS certificates from two ports of one host are
**one fact observed twice** — a wildcard certificate deployed to 443 and 8443 — and counting them
as two merges on evidence that is really singular. `IdentityKey.Source` names the service, and
the rule counts distinct sources rather than keys.

**A disagreement at equal-or-higher strength is not outvoted.** A candidate whose SSH host key
contradicts the observed one has said something that matters more than any number of agreeing
addresses. Letting weight of agreement carry it is how a merge happens for reasons nobody can
reconstruct afterwards.

The resolver is a **pure function** — `internal/domain`'s rule, and not tidiness: a wrong merge
interleaves two hosts' findings and timelines irreversibly, so being able to replay every decision
from stored observations against a corrected rule is what makes the rule correctable. `now` and
the window are parameters rather than reads for the same reason.

### 6. Attaching is not merging

ADR-007's "IP alone never merges" leaves the commonest observation in the system — an open port on
a host with no TLS and no SSH — with two bad outcomes: a new asset on every scan, which explodes
the inventory, or the unresolved queue, which explodes the queue. Neither is what an operator
means by "scan this /24 again".

So there is a fourth decision. **Attach** says this observation belongs to an asset that currently
holds the observed address and was seen at it inside the window. It records **no identity key**.
It asserts only what the address table already asserts, and it expires on its own. **Merge** says
these are the same host, which is permanent.

That is also what makes `ip_window` a window rather than a label: outside it, the address is
evidence of nothing and the observation becomes a new asset.

An attach requires the address key to **agree**, not merely for the candidate to have been seen
somewhere recently. An earlier version checked a caller-supplied timestamp and a key's presence,
which attaches an observation of one address to an asset holding another; a test fixture made
exactly that mistake, which is why it is a check rather than a convention.

## Consequences

**Week 5's deliverable is reachable, and only because of §2.** A host with neither TLS nor SSH
still has only `ip_window` and still accumulates a new asset when its address changes. That is
ADR-007's designed degradation — identity quality falls off gracefully rather than guessing — and
it is why a moderate key was worth a protocol implementation.

**Which of ADR-007's keys are unreachable, and what unblocks each, is recorded in one place**:
the table comment in `internal/domain/identity.go`. A key table that is mostly aspirational should
say so where the code reads it, rather than leaving the next session to rediscover it.

**The engine's import allowlist grew by five**: `crypto/sha256` and `encoding/base64` to
fingerprint a certificate and a host key, `crypto/ecdh` for the ephemeral key, `encoding/binary`
for packet framing, and `reflect` test-only in the process shell. Each is arithmetic over bytes;
none opens anything. `golang.org/x/crypto/ssh` is the one that was refused, which is the entry
worth remembering.

**A wire-to-engine translation dropped `Kind` silently**, and the SSH probe was absent from every
chain until a capture showed one connection where there should have been two. Both sides compiled
and the receiver saw a zero value. `cmd/cvap-engine-fingerprint/translate_test.go` now asserts by
reflection that no field of a probe or a match is zero after translation — a hand-written field
list would have been the same failure, since the person who forgets to translate a field is the
person who would forget to list it.

**`services` gained the identification evidence** (migration 0030): method, confidence, softmatch,
solicited, safety mode, probe, and the certificate and host key as jsonb on the row. The jsonb
choice is ADR-048 §5's argument carried into the derived model. A schema audit found the
softmatch constraint rejected an empty product string, which is exactly what the engine writes for
a softmatch — the constraint would have made the feature unwritable.

## Alternatives considered

**Stretch `MaxProbePayload` to cover a handshake.** Rejected: the number would have bounded
nothing and the policy would have read as though it covered something it did not.

**Use `golang.org/x/crypto/ssh`.** Rejected: see §3.

**Declare identity-bearing probes with a wire boolean.** Rejected: any pack could then exempt its
probe from the chain's cap economy. Deriving it from the kind keeps the set amendment-gated.

**Skip SSH and ship a resolver that works for TLS-bearing hosts.** Rejected as not being the
deliverable. Most of a real estate is Linux with SSH and no TLS.

**Let weight of agreement outvote a contradicting key.** Rejected: it is the mechanism by which a
wrong merge becomes unexplainable.
