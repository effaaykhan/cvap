# ADR-019: Knowledge data is signed; offline import supported

**Status:** Accepted
**Date:** 2026-08-30

## Context

Rules are code-adjacent: they carry detection logic that executes against customer
infrastructure. Some of them run on Scan Points (ADR-013), which sit inside customer networks
by design. A compromised rule feed is therefore a fleet-wide compromise of every customer
simultaneously, with our own distribution channel as the delivery mechanism. The rest of the
knowledge data is not executable but is just as load-bearing: tampered advisory or KEV data
silently suppresses real findings, which is a quieter failure and no less serious. Meanwhile
§4 requires the Knowledge Plane to be fully offline-capable, and §7 requires an offline update
path for rule packs **and** knowledge data — air-gapped customers ask on the first call.

## Decision

**All knowledge data is versioned and cryptographically signed**, and all of it has an
offline import path — rule packs, NVD CVE and CPE data, vendor advisories, KEV, EPSS, and the
fingerprint corpus. Scan Points verify the signature before loading a rule pack and refuse an
unsigned or invalid one; Core verifies signatures before ingesting any knowledge bundle.
`RULE_PACK.signature` and `RULE_PACK.version` record this for rule packs, and every other
knowledge bundle carries the equivalent.

Distribution is **notification plus fetch**, never inline: the dispatch stream carries a
`RulePackUpdate` announcing `pack_id`, version and signature digest, and the Scan Point
downloads from a dedicated `RulePacks` service (ADR-005). A multi-MB bundle on the dispatch
stream would head-of-line block job assignment. A Scan Point that **refuses** a pack — bad
signature, bad format, failed fetch — reports that upstream as `RulePackStatus`; silent
fail-closed inside a network we cannot observe is the mysterious failure ADR-022 argues
against. Scan Points also report currently loaded pack versions on connect, because offline
import means a pack can arrive out-of-band and Core would otherwise not know what is live.

The **offline bundle import path is required, not optional**: an air-gapped operator must be
able to move a signed bundle in by hand and get byte-identical verification, with no reduction
in guarantees. It follows that **no query path may depend on a live call to an external
knowledge source** — matching (ADR-014) reads only from ingested local data, so an air-gapped
deployment is a stale deployment, never a broken one.

## Alternatives considered

**Rely on TLS for the transport and skip signing.** Rejected: TLS protects the channel, not
the artefact. It gives no protection against a compromised build or distribution host, and it
provides nothing at all for the offline import path where there is no channel.

**Sign only packs containing scan-point rules, since core rules run in our own trust
boundary.** Rejected: it creates two handling paths for the same artefact type, and the
core-side rules are what generate every finding a customer acts on — a tampered core rule
that suppresses detections is an equally serious outcome, just a quieter one.

**Sign rule packs only, and treat advisory and CVE data as public reference data needing no
signature.** It is public data, freely downloadable, so this looks defensible. Rejected: it is
the authority ADR-014 matches against, so tampering with a fixed-version row silently converts
a real finding into a clean result. Public provenance is not integrity, and the offline path
has no transport security to fall back on.

**Online-only distribution, with air-gapped customers handled by exception.** Rejected:
air-gapped customers exist in this market and ask on the first call, and "handled by
exception" means an unverified sideload, which is the worst of both.

**Require Scan Points to fetch and verify rules directly from a signing service or CDN.**
More moving parts in the fleet, and it breaks ADR-005's posture: a scan point's only outbound
connections are to Core's own services, so it never fetches from a third party. Adding one
would mean a new egress rule at every customer and a new supply-chain dependency reachable
from inside their network.

## Consequences

A compromised distribution host does not become a compromised fleet, and tampered advisory
data cannot silently suppress findings. Air-gapped operation is a first-class path rather than
a workaround, which matters for the customers most likely to buy, and it is the concrete form
ADR-017's mode-conditional behaviour takes for the Knowledge Plane. The costs are real key
management — signing key custody, rotation, and a story for what happens if it is compromised
— plus verification code on the scan point that must fail closed, a signing and bundling step
on every knowledge pipeline rather than only on rule builds, and a bundle format that must
stay compatible with scan points running months-old builds (ADR-022).

## Review trigger

Revisit key rotation policy on any suspicion of signing key exposure, and revisit the bundle
format before any change that would break a scan point inside the supported version window.
