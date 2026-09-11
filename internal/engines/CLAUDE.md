# internal/engines

Scan engines. One directory per engine, each running as a **separate process** hosted by
the scan point runtime and communicating over the job contract (ADR-027). See
`/add-scan-engine` before creating a new one.

Rules:

- Engines emit observations only.
- No database access, no control plane imports, no state between tasks, nothing on disk.
- **Engines receive resolved, pre-authorised targets and may not construct new ones.**
  Anything discovered mid-scan — a redirect, a DNS answer, a referenced host — returns to
  the runtime for authorisation before the engine may touch it. Scope enforcement is at
  exactly two sites, Core and the runtime, never in an engine (ADR-024, ADR-027).

  An engine therefore holds no scope data: no allowlist, no exclusion list, no CIDR
  arithmetic. If an engine needs to know whether an address is in scope, the design is
  wrong — it should be asking the runtime, not deciding.
- **Engines never receive raw credential material.** The runtime holds the credential and
  passes a session handle or a short-lived derived proof (ADR-020). For SSH the engine opens
  the connection itself and authenticates over the runtime's signing-agent socket on fd 3 —
  signatures, never the key (ADR-086). An engine that crashes cannot leak what it never held.
  Core dumps are disabled on engine processes.
- The runtime allocates a rate slice; the engine stays inside it and reports actual send
  counts. Engines do not read the platform ceiling and do not coordinate with each other —
  the aggregate is bounded by the runtime's allocation, not by cooperation (ADR-024).
- Bounded reads and timeouts on everything. Engines parse hostile input by design — a
  banner from an attacker-controlled host is untrusted input and an unbounded read is a
  denial of service against your own fleet.
- Honour context cancellation within seconds so the kill switch works. The runtime sends
  `SIGTERM` then `SIGKILL` after a short grace; clean shutdown is the engine's chance to
  finish a partial observation, not a veto.
- Detection establishes evidence without achieving impact. See `/cvap-invariants`.

## The engines that send packets

`credhost` holds `net` and `x/crypto/ssh` (ADR-086): it dials port 22 of a resolved target and
runs two read-only commands over an authenticated session, emitting one `package` observation
per host. `discovery` holds `net` (ADR-047). `fingerprint` holds `net` plus four crypto imports (ADR-048),
and it is the only place in this repository where `InsecureSkipVerify` is correct — a verifying
dial fails on exactly the certificates worth reporting, so it would return an error where the
evidence should be. It appears **once**, in `inspectOnlyTLSConfig`, whose name is the argument,
and a mutation flips it and requires the tests to fail. Do not write a bare `tls.Config` at a call
site in that package.

Certificates from a scanned host are **attacker-controlled by definition**. Chain depth, SAN
count, extension count and name length are all bounded, each with a mutation, and truncation is
always reported alongside the untruncated count.

`enginerate` is the shared packet budget. It is shared rather than copied because `make safety`
asserts a wire-to-charged ratio against **one** model; two copies means the gate binds whichever
the tests happen to exercise while the other drifts.

Run `scan-safety-auditor` on any change here.
