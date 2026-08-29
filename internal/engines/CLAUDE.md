# internal/engines

Scan engines. One directory per engine, each behind the interface in
`internal/scanpoint/engine.go`. See `/add-scan-engine` before creating a new one.

Rules:

- Engines emit observations only.
- No database access, no control plane imports, no state between tasks, nothing on disk.
- Bounded reads and timeouts on everything. Engines parse hostile input by design — a
  banner from an attacker-controlled host is untrusted input and an unbounded read is a
  denial of service against your own fleet.
- Re-check every target against the exclusion list before sending, even though Core
  already did. This duplication is deliberate.
- Honour context cancellation within seconds so the kill switch works.
- Detection establishes evidence without achieving impact. See `/cvap-invariants`.
