# ADR-108: A host that answers is not a host that exists

**Status:** Accepted
**Date:** 2026-09-29
**Follows:** ADR-006 (correlation is the only thing that writes an asset), ADR-103 (an open
port is durable evidence — which saw this problem, measured it at 19 of 19 hosts, and
deferred it: *"Revisit when service identification can distinguish a host answering from a
middlebox"*), ADR-007 (identity and merge), ADR-016 (observations are ephemeral).
**Scope:** This does not add a scan capability. It adds a verdict about evidence CVAP
already holds, in the layer that already decides what an asset is.

## Context

The discovery engine works. It probes an address, something completes a TCP handshake, and
it emits an honest `port` observation saying so. Correlation promotes that to an asset
(ADR-006). Every step is behaving as designed, and the result is mostly fiction.

Measured on the two authorised /24s, 2026-09-29, on the dev database:

```sql
SELECT count(*) FROM assets;                                    -- 512
```

512 is **exactly 2 × 256**: every address in both ranges became an asset, including the
four that cannot be hosts at all.

```sql
SELECT host(ip_address) FROM asset_addresses
 WHERE host(ip_address) LIKE '%.0' OR host(ip_address) LIKE '%.255';
-- 10.200.10.0 (1 port), 10.200.10.255 (4 ports), 10.200.11.0 (5 ports), 10.200.11.255 (0)
```

A network address with five open ports is not a finding about the estate. It is a finding
about the network.

The port distribution says what is answering:

```sql
SELECT port, count(*) FROM services GROUP BY port ORDER BY 2 DESC;
--  5060/tcp  473  (92.4% of assets)      445/tcp  330  (64.5%)
--  2000/tcp  398  (77.7%)                135/tcp  330  (64.5%)
--                                       3389/tcp  247  (48.2%)
```

SIP on 92% of a /24 pair is one device answering for a range, not an estate of soft
switches.

### The discriminator, and it is not port count

The temptation is to suppress a port that appears too often. That is wrong: a managed fleet
legitimately runs SSH on every host, and a rule keyed on ubiquity would delete the best-run
estates first. The real signal is that **a responder answers and then says nothing**:

```sql
SELECT port, count(*) AS rows,
       count(DISTINCT coalesce(product,'')||'/'||coalesce(version,'')) AS identities,
       count(*) FILTER (WHERE product <> '') AS with_product
  FROM services GROUP BY port;
```

| port | rows | distinct identities | with a product |
|---|---|---|---|
| 5060 | 473 | **1** | **0** |
| 2000 | 398 | **1** | **0** |
| 135 | 330 | **1** | **0** |
| 445 | 330 | **1** | **0** |
| 3389 | 247 | **1** | **0** |
| 80 | 179 | **1** | **0** |
| **22** | **40** | **10** | **28** |

Six ports answer hundreds of times and never once resolve to a product. Port 22 answers
forty times and yields ten different real identities — OpenSSH, Dropbear, MySQL are the only
three products the whole estate produced. A real service population is *diverse*; a
responder is *uniform*, because it is one device wearing every address.

That separation is enormous, decidable from data CVAP already stores, and needs no second
scan.

### Why this outranks everything else open

Every downstream number starts from the host list. 0 of 512 assets carry an OS family or a
distro release, so OS attribution has nothing to work on and advisory matching cannot run.
2,628 service rows yield 3 distinct products. 512 assets produced 2 findings — and both are
on hosts that are demonstrably real. The pipeline is not under-reporting; it is reporting
faithfully about hosts that are not there.

## Decision

**1. Existence is a verdict carrying evidence, not the absence of a timeout.** An address
that answered is an *observation*. Whether a host exists there is a judgement CVAP makes,
records, and can be asked to justify — the same contract as every other claim in this
system. Today the judgement is implicit and always "yes", which is why it is never wrong in
a way anyone can see.

**2. The verdict is `present` / `responder` / `unknown`, and it is a property of the
ADDRESS, not of the asset.** One middlebox answering for 500 addresses is one device, and
the addresses it covers are not assets. Modelling it on the address keeps the merge rules
(ADR-007) untouched and means a host that later proves itself real at that address can be
promoted without unpicking an asset identity.

**3. The discriminator is identity diversity, not ubiquity.** A port is treated as a
responder artefact on a range when it answers across that range and resolves to no distinct
identity. Ubiquity alone is never sufficient — it would penalise a uniformly managed
estate, which is the opposite of the intent. The threshold is a POLICY LEVER with a stated
default, not a constant compiled in: the measured separation here is 92.4%/0 identities
against 7.8%/10, so any sane default separates them, and a tenant whose network genuinely
looks different must be able to move it without a release.

**4. An address that is structurally impossible is refused outright.** The network and
broadcast addresses of a scanned CIDR are not hosts, whatever answers there. This needs no
heuristic and no threshold; it is arithmetic. Four of the 512 are exactly this.

**5. Nothing is deleted.** A `responder` address keeps its observations, its services and
its history, and is *suppressed from the estate* rather than removed from the database. Two
reasons, and the second is the one that matters: a verdict about a live network can be
wrong, and a deletion cannot be reviewed. This is the same shape as a retired ATT&CK
technique (ADR-105) and a seen-only port (ADR-103) — the row survives, its meaning is
labelled.

**6. The suppression is STATED, with its count and its reason.** "512 assets" and "29
assets, 483 addresses suppressed as responder artefacts behind one device" are different
claims, and the second is the true one. An operator must be able to see what was suppressed
and why, and to disagree. Silence here would replace one wrong number with another wrong
number that happens to be smaller.

**7. The decision is pure and lives in `internal/domain`.** `internal/correlate` gathers the
evidence and applies the verdict; the rule itself is a function of observations with no I/O,
so it can be replayed over history when the rule is corrected — the same split ADR-006
requires for merges, and for the same reason: this judgement will be wrong at first.

## Alternatives considered

**Filter at the scan point.** Rejected, and not narrowly. ADR-006 exists because judgement
in a distributed fleet running months-old builds is judgement nobody can audit or replay.
A scan point that decided which addresses were real would discard the evidence for that
decision at the moment it made it. Scan points emit observations; Core decides.

**ICMP-only liveness.** Rejected. It does not separate the populations — a middlebox
answering TCP for a range will answer ICMP for it too — and CVAP does not run privileged,
so raw ICMP is not available in the deployment shape this is built for. It would also make
existence depend on a protocol most estates filter, trading false positives for false
negatives with no gain in evidence.

**Suppress any port above a ubiquity threshold.** Rejected as the primary rule; see
decision 3. It deletes the well-managed estate first, which is precisely backwards, and it
throws away the real signal (identity) in favour of a proxy for it (frequency).

**Require a banner before believing a host exists.** Rejected. Plenty of real services do
not banner, and several deliberately do not. This would suppress exactly the quiet,
hardened hosts an operator most wants inventoried.

**Delete the phantom assets.** Rejected — decision 5. A wrong deletion is unreviewable, and
this rule WILL be wrong somewhere: a real host sitting behind the same middlebox, on a port
the middlebox also answers, is the case that will bite.

**Do nothing and document it.** This was the status quo since ADR-103 named the problem, and
it is what made the measurement above possible. It is no longer defensible: a documented
limitation that every downstream number silently inherits is not a limitation, it is a wrong
answer with a footnote.

## Consequences

The estate count will fall sharply and become defensible. On the measured data the honest
population is the 29 assets that resolved to a real product, against 512 reported — so
this is not a refinement, it is the difference between an inventory and a list of addresses
that answered.

OS attribution and advisory matching stop being starved by noise, though neither is fixed by
this alone. The seen-only port rows ADR-103 introduced remain correct and become far more
useful, because the ones that survive will belong to hosts that exist.

What this does NOT do is detect the middlebox. It detects the *signature* of one and
declines to invent hosts from it. Naming the device, or attributing the addresses it covers
to it, is a separate decision needing evidence this does not gather.

The rule will be wrong in both directions at first, which is why decisions 5, 6 and 7 exist
together: nothing is destroyed, the suppression is visible and arguable, and the verdict can
be replayed over stored history when the rule improves.

## Review trigger

Revisit when a real host is suppressed and an operator has to argue with the verdict — that
is the failure this ADR expects and the one the evidence trail exists to settle. Revisit
decision 3 if an estate appears whose genuine services are uniform enough to collide with
the responder signature. Revisit decision 2 if middlebox attribution is ever built, since
"these 500 addresses are one device" is a claim about an asset, not about 500 addresses.
