# ADR-020: Credentials just-in-time, scoped, memory-only on scan points

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 covered credential storage well and delivery not at all. Credentialed assessment (Phase 4)
requires SSH, WinRM, SNMP and cloud credentials to reach a Scan Point — the component most
exposed to a hostile network, and the one whose compromise the threat model explicitly
assumes. A compromised scan point must not yield the customer's domain admin password.

## Decision

Credentials are delivered **just-in-time with the job** and scoped to that job's targets —
never a bulk sync of the credential store to a scan point. They are short-TTL and
**memory-only**, never written to disk on the scan point, and are **zeroised on job
completion, lease loss, or abort** (ADR-012 makes lease loss a hard self-abort). Where
feasible, prefer mechanisms in which the secret never leaves Core at all: Kerberos ticket
delegation, SSH certificates with minute-scale validity. Every release is recorded as a
`CREDENTIAL_GRANT` — profile, job, target scope, expiry, and the recipient's certificate
fingerprint — and as an audit event. `CREDENTIAL_PROFILE.secret_ref` is a vault pointer,
never plaintext.

**Credentials stop at the Scan Point runtime.** Engine processes (ADR-027) never receive raw
credential material: the runtime holds the credential, establishes the authenticated session,
and hands the engine a **session handle** — or, where that is impractical, a short-lived
derived token, never the credential itself. **Core dumps are disabled on engine processes**,
as a backstop for anything that must live in engine memory, relying on kernel page-zeroing at
process death. This is what makes an engine crash survivable: a process that never held the
secret cannot leak it, and a `SIGKILL`ed process cannot zeroise.

Every grant declares a `cred_kind` — `SESSION_HANDLE`, `KERBEROS_TICKET`, `SSH_CERT`,
`DERIVED_TOKEN` or `RAW_SECRET`. The preferred secret-free mechanisms carry structurally
different material, and overloading one opaque `material` field to mean different things per
protocol is exactly the semantic drift ADR-022 forbids.

## Alternatives considered

**Sync the credential store to each scan point and cache locally.** The conventional design,
and far simpler operationally — it survives Core being unreachable. Rejected outright: it
means every scan point in every hostile network holds the customer's full credential set at
rest, so one compromise yields the estate.

**Deliver per-job but allow encrypted on-disk caching for restart resilience.** Rejected:
anything written to disk on a scan point survives the process, and the decryption key must
also be on that host. It converts a memory-scraping attack into a file read.

**Never send credentials at all; proxy every credentialed operation through Core.** Strongest
isolation, and rejected on feasibility: the scan point exists precisely because Core cannot
reach the target network. Proxying would require the inbound path ADR-005 forbids.

**Long-lived scan-point service accounts in the customer's directory.** Moves the problem
rather than solving it, and produces a standing privileged account whose compromise is
undetectable.

## Consequences

Blast radius of a scan point compromise is bounded to the credentials for jobs in flight, for
the remaining seconds of their TTL, scoped to those targets. Every credential release is
auditable against a job and a device identity. The costs: Core must be reachable to start a
credentialed job, so an offline scan point cannot begin one; TTLs must exceed realistic job
durations or long credentialed jobs fail mid-run; zeroisation must be correct in a garbage-
collected language, which requires deliberate handling rather than trusting the runtime; and
the preferred secret-free mechanisms are per-protocol work that will not all land at once.
Keeping credentials out of engine processes concentrates the most sensitive code in the Scan
Point runtime, which must own session establishment for every credentialed protocol — real
work per protocol, and one component whose correctness carries the whole guarantee.

## Review trigger

Revisit TTL and scoping if credentialed jobs fail at a measurable rate from credential expiry
mid-job, and revisit the delegation preference as each protocol's secret-free mechanism
becomes available.
