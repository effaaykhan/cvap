# internal/scanpoint

Scan point runtime: connection, lease client, engine host, result buffering.

Rules:

- Outbound only. This package never listens.
- Never imports `internal/control` or `internal/store`.
- Emits observations. Never constructs an Asset or Finding.
- Lease renewal failure means self-abort and credential zeroise, on every path including
  panic recovery. Not "log and continue".
- Credentials live in memory for the life of the job and nowhere else. No struct holding
  credential material may have a String() or a json tag that exposes it.
- Every engine invocation gets the job's ScanConstraints and must apply them on the send
  path, not merely receive them.
- Results buffer to local encrypted storage when Core is unreachable, and resume.

Run `scan-safety-auditor` on any change here.
