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
- **Engines never receive raw credential material.** The runtime establishes the
  authenticated session and passes a session handle, or a short-lived derived token
  (ADR-020). An engine that crashes cannot leak what it never held. Core dumps are disabled
  on engine processes.
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

Run `scan-safety-auditor` on any change here.
