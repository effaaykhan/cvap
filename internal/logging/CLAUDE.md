# internal/logging

Process-wide structured logging. `log/slog`, JSON handler, redaction on by default.

Rules:

- **Construct loggers through `logging.New`.** A bare `slog.NewJSONHandler` has no
  redaction, which is how a credential reaches a sink.
- Redaction is key-based and runs on every attribute, including inside groups. The
  sensitive-key list is deliberately narrow: `dedup_key`, `identity_key`, `host_key` and
  `signature_digest` are load-bearing and must stay readable. Widening the list until useful
  fields disappear is how the redactor gets removed.
- It cannot see through a type's own rendering, so a hand-written type holding credential
  material must render itself safely. **It MUST implement `String()`, `LogValue()` and
  `MarshalJSON()` returning a redacted form, and MUST NOT provide any other accessor that
  renders the value implicitly.** The single way to obtain the secret is a method named
  `Reveal()` — named that so it is conspicuous at every call site and greppable.

  Implementing nothing is *not* the safe option, which is the trap this rule exists to close:
  a bare struct with an unexported string field still prints its contents under `%v`, because
  `fmt` reaches unexported fields by reflection. The danger is a type that renders by default,
  not a type that renders at all. No json tags exposing the value either (ADR-020).

- **The secret is stored in a `func() string` field, never a `string` field (ADR-035).** The
  methods above are necessary and not sufficient: `fmt` calls *none* of them when the value
  sits in an unexported field of another struct, because `reflect.Value.CanInterface` is false
  there. Every method-based defence is skipped at once. A func value has no rendering at any
  verb in any position, which is what actually closes it — measured, not assumed:
  a `string` field gives `{%!d(string=SECRET)}` and `{{SECRET}}`; a `func() string` field
  gives `{4824512}` and `{{0x499dc0}}`.
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
