# internal/logging

Process-wide structured logging. `log/slog`, JSON handler, redaction on by default.

Rules:

- **Construct loggers through `logging.New`.** A bare `slog.NewJSONHandler` has no
  redaction, which is how a credential reaches a sink.
- Redaction is key-based and runs on every attribute, including inside groups. The
  sensitive-key list is deliberately narrow: `dedup_key`, `identity_key`, `host_key` and
  `signature_digest` are load-bearing and must stay readable. Widening the list until useful
  fields disappear is how the redactor gets removed.
- It cannot see through a type's own rendering. **No hand-written type holding credential
  material may implement `String`, `MarshalJSON` or carry json tags that expose it** — that
  rule lives in `internal/scanpoint` and this package is why it matters (ADR-020).
- **The generated protobuf types break that rule and cannot be made to follow it.**
  `protoc-gen-go` emits `String()` on every message unconditionally, and it renders every
  field — including `EnrollRequest.enrollment_token` and `CredentialGrant.material`, and
  anything carrying them, such as `CoreMessage`. Marking the fields
  `[debug_redact = true]` does not help: protobuf-go consults the option nowhere in its
  encoding path, re-verified at v1.36.11. **Log a protobuf message only through `logging.Proto` /
  `logging.ProtoAttr`**, which reads the marker itself and applies `IsSensitiveKey` to field
  names as well. `.github/scripts/check_secret_logging.py` (`make secret-logging`) fails the
  build if one reaches a logging call any other way.
- The one gap that gate cannot close is a gRPC payload-logging interceptor, which sees
  messages reflectively. Forbidden on Enrollment and Dispatch by contract comment, and held
  by human review.
- Adding a key to the sensitive list needs a test in `logging_test.go`. Removing one needs
  a reason in the commit message.
- No log line carries a raw credential, a session handle, or a derived token — not at debug
  level, not behind a flag.
