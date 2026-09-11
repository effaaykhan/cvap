# ADR-092: The credentialed route is proven end to end on the lab, and both SSH clients offer one host-key preference

**Status:** Accepted
**Date:** 2026-09-11
**Follows:** ADR-091 (frozen). This records the first run of the route ADR-091 built through the
real pipeline, the defect that run found, and what it does and does not discharge.

## What ran

`test/e2e/TestCredentialedInventoryOverTheWire` drives the shipped binaries as separate processes
over real mTLS against `lab/targets/ssh-plain` (10.20.0.12, Debian 12), whose image now carries a
`lab` account with an ed25519 key generated at build time — nothing committed. The test takes the
key, the host key and the expected inventory from the container the way `ground-truth.sh` does
(`docker cp`, `docker exec dpkg-query`), never from the scanner.

Measured, in order: Core resolved the profile's secret under `CVAP_CORE_SECRET_FILE_ROOT`, wrote
the `credential_grants` row and the `credential.granted` event with `trust_source = observed`, sent
the grant behind the assignment; the runtime validated the assignment, built the ADR-086 agent and
spawned `cvap-engine-credhost` with the socket on fd 3; the engine authenticated with signatures
alone, read `/etc/os-release` and the dpkg inventory, and submitted one `package` observation to
Ingest; the observation's family, release and the versions of `openssh`, `glibc` and `dpkg` equal
what the container reports of itself; the submission is accepted and complete, the job completed,
the grant record closed on the attestation, and no `credentials_not_attested` event was raised.
Sabotaging the expected versions fails the test at the comparison, so the assertion is against the
container, not against the engine's own output.

The test is gated like the corpus scan half: it skips, naming the lab, when 10.20.0.12:22 does not
answer, and `CVAP_REQUIRE_LAB=1` makes that fatal. It runs in the CI job that stands the lab up.

## The defect the run found

The first run failed at the SSH handshake with `host key mismatch`. The fingerprint engine
performs its own key exchange and offers `ssh-ed25519` first, so the fingerprint discovery
records — the observed trust material of ADR-091 §4 — is the ed25519 host key. The credentialed
client used `x/crypto/ssh`'s default host-key order, under which the server presented a different
key. A server holds several host keys and presents whichever the client prefers first; two clients
with two orders see two keys for one host, and the observed fingerprint verifies nothing. The
observed path could never have succeeded on any host, and no unit test could see it: each client
was correct alone (§9 5.11, correct at the seam's two ends and wrong at the seam).

**Decision:** one preference, `internal/sshalgo.HostKeyPreference`, a string list with no imports,
offered by both the fingerprint engine's KEXINIT and the credentialed client's `ClientConfig`. The
engine import allowlist admits it because it grants no capability. The key discovery records is,
by construction, the key the credentialed handshake verifies.

## What this discharges, and what it does not

- ADR-088's "no credhost engine has emitted a package observation through the pipeline" is no
  longer true: the fleet path has produced a credentialed observation end to end, on real
  processes, against a host whose truth was read independently.
- ADR-088's named acceptance — `.146`'s sixteen unauthenticated OpenSSH findings closing as
  `refuted_by_credentialed` through the real pipeline — is **still open**. The lab target has no
  inferred findings to refute. That run needs the three Phase 4 hosts re-added to `lab/scope.txt`
  and the deploy stack rebuilt on this tree (the deploy image now builds the credhost engine and
  the compose carries `CVAP_CORE_SECRET_FILE_ROOT`), and either an operator pin or an intrusive
  discovery pass first: the observed path needs a captured host key, and the fingerprint probe
  travels only under intrusive mode (ADR-021), which is why the deploy estate has none.
- The credentialed engine remains outside the rate and fragile model (ADR-091's recorded gap).

## Review trigger

The `.146` run. Its numbers belong in their own record, not in an edit to this one.
