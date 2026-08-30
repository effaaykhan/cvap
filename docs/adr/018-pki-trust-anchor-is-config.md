# ADR-018: PKI trust anchor is configuration, not assumption

**Status:** Accepted
**Date:** 2026-08-30

## Context

Scan Point identity rests on mutual TLS (ADR-005), which requires a certificate authority.
This is the part of the deployment story that genuinely differs between modes: in SaaS, Core
is a CA issuing identities to customer-deployed scan points reaching across the internet;
on-prem, the customer's Core is the CA for a local fleet. If the trust anchor is hard-coded
to our SaaS CA, on-prem needs a different enrollment path — and ADR-017's single-codebase
commitment fails at the first component.

## Decision

The trust anchor is **configuration, not an assumption baked into the binary**. Enrollment is
byte-identical in both modes: an enrollment token is exchanged exactly once for a client
certificate, certificates rotate before expiry, and revocation is central and immediate. The
certificate fingerprint is the Scan Point's identity in the audit log and in
`SCAN_POINT.cert_fingerprint`, and is what `CREDENTIAL_GRANT.delivered_to_fingerprint`
records (ADR-020).

## Alternatives considered

**Hard-code the SaaS CA and treat on-prem as an exception.** Rejected: it makes the on-prem
enrollment flow a second code path in the most security-sensitive component, violating
ADR-017 exactly where it matters most.

**Use a public CA (Let's Encrypt or similar) for scan point certificates.** Rejected: client
certificates for machine identity are not what public CAs issue, it requires internet
reachability that air-gapped deployments do not have, and it removes our ability to revoke a
scan point immediately.

**Long-lived shared secrets or API keys instead of certificates.** Simpler to implement and
to support. Rejected: a shared secret on a scan point in a hostile network is a credential
that cannot be rotated per-device or revoked per-device, and it gives no cryptographic
identity to bind audit records to. Scan point compromise is assumed (§18.3), so per-device
revocable identity is a requirement.

**Delegate to an external PKI or HSM the customer already runs.** Attractive for large
enterprises and worth supporting eventually, but making it mandatory blocks the small
deployment. Trust anchor as configuration leaves the door open without requiring it now.

## Consequences

One enrollment implementation, one test path, and an on-prem install that exercises the same
code as SaaS. Per-scan-point revocation is immediate, which is what bounds blast radius when
a scan point in a hostile network is compromised. The costs: Core must operate a CA
correctly — issuance, rotation, revocation distribution and the security of the signing key —
in every deployment, including at customers with no PKI expertise, and enrollment token
handling becomes a security-sensitive surface of its own.

## Review trigger

Revisit when a customer requires their existing enterprise PKI or an HSM as the trust anchor,
which the configuration seam should accommodate; revisit the rotation window if certificate
expiry is ever the cause of a fleet outage.
