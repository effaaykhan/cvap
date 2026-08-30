# internal/logging

Process-wide structured logging. `log/slog`, JSON handler, redaction on by default.

Rules:

- **Construct loggers through `logging.New`.** A bare `slog.NewJSONHandler` has no
  redaction, which is how a credential reaches a sink.
- Redaction is key-based and runs on every attribute, including inside groups. The
  sensitive-key list is deliberately narrow: `dedup_key`, `identity_key`, `host_key` and
  `signature_digest` are load-bearing and must stay readable. Widening the list until useful
  fields disappear is how the redactor gets removed.
- It cannot see through a type's own rendering. **No type holding credential material may
  implement `String`, `MarshalJSON` or carry json tags that expose it** — that rule lives in
  `internal/scanpoint` and this package is why it matters (ADR-020).
- Adding a key to the sensitive list needs a test in `logging_test.go`. Removing one needs
  a reason in the commit message.
- No log line carries a raw credential, a session handle, or a derived token — not at debug
  level, not behind a flag.
