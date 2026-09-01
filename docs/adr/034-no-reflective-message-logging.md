# ADR-034: No interceptor, middleware or tracing layer may render message bodies

**Status:** Accepted
**Date:** 2026-09-01

## Context

Two fields on the scan point wire contract carry credentials:
`EnrollRequest.enrollment_token`, a bearer credential that yields a full fleet identity, and
`CredentialGrant.material`, which is access to the customer's estate. Both are marked
`[debug_redact = true]`.

That marker does nothing on its own. protobuf-go consults `debug_redact` nowhere in its
encoding path — re-verified at v1.36.11 — so `String()` on those messages renders the secret
in full, and `protoc-gen-go` emits `String()` on every message unconditionally.
`internal/logging` redacts on the attribute *key* and cannot see inside a value a type renders
for itself. `.github/scripts/check_secret_logging.py` closes the source-level gap: it fails
the build if a secret-bearing type reaches a logging or formatting call.

It has one gap, stated in its own docstring since it was written:

> The remaining gap is a gRPC payload-logging interceptor, which sees the messages
> reflectively and defeats any source-level check.

A source-level check cannot see this. An interceptor receives `any`, calls something generic,
and never names `EnrollRequest` anywhere. The gate would pass. The token would be in the log.

Until now this was recorded as a comment in `enrollment.proto` and in
`internal/logging/CLAUDE.md`. Both are read by people editing protos or logging — not by
whoever adds observability in month five, which is exactly when a request-logging interceptor
or an OpenTelemetry span-with-payloads gets proposed, by someone doing something reasonable.

## Decision

**No gRPC interceptor, middleware, or tracing layer may render message bodies reflectively, on
any of the four scan point services** — Enrollment, Dispatch, Ingest and RulePacks (ADR-005).

Concretely, none of the following is permitted on those services:

- a unary or stream interceptor that logs, serialises or samples request or response messages;
- `otelgrpc` or any tracing integration configured to record message payloads;
- a generic `slog.Any("request", req)` in an interceptor, or `fmt.Sprintf("%v", req)`;
- a debug or verbose mode that enables any of the above behind a flag.

What *is* permitted, and is what an interceptor is legitimately for: method name, status code,
duration, peer certificate fingerprint, tenant id, request id, message sizes. Everything an
operator needs to answer "what happened, to whom, how long did it take" without rendering what
was carried.

Logging a specific message stays possible through `logging.Proto` / `logging.ProtoAttr`, which
read the `debug_redact` marker themselves and apply `IsSensitiveKey` to field names. That is a
deliberate, named call at a specific site — reviewable in a way a reflective layer is not.

`check_secret_logging.py`'s docstring names this ADR as the gap it cannot see, so the gate
points at the control that covers it.

## Alternatives considered

**Keep it as a contract comment.** What we had. Rejected on audience: a proto comment is read
when editing the proto. The person adding request logging is editing a server setup file and
has no reason to open `enrollment.proto`, and the interceptor they add will look correct in
review to anyone who has not read that comment.

**Extend the gate to detect interceptors.** Attractive, and partially possible — a lexical
check could flag `grpc.UnaryInterceptor` near a logging call. Rejected as the primary control
because it is unsound in both directions: it cannot see an interceptor assembled from a helper
in another package or supplied by a dependency, and it would flag legitimate interceptors that
log only metadata. A check that both misses the real case and cries wolf on the safe one gets
switched off. Worth adding later as a lint that *warns*; not worth pretending it is the
control.

**Redact inside the interceptor instead of banning payload rendering.** This is how most
systems do it: an allowlist or denylist of field names applied reflectively. Rejected because
it re-implements `logging.Proto` in the one place with no type information, and it fails open
— a field added to the contract later is rendered unless someone remembers to add it to the
list. ADR-022 makes the contract additive-only, so new fields are certain.

**Strip the secrets from the wire instead.** The strongest fix, and unavailable: the token has
to reach Core to be redeemed, and credential material has to reach the scan point to be used.
They are on the wire because that is what they are for.

## Consequences

Observability on the scan point services is built from metadata, which is the right shape
anyway — a distributed trace carrying a fleet credential is a credential in every span store,
sampling backend and screenshot of a trace view.

The costs are real. Debugging a protocol problem is harder without payload capture, and the
honest answer is that a developer reproduces it against a lab scan point where the token is
worthless, rather than turning on payload logging in production. Anyone integrating a
standard gRPC observability package must check its defaults rather than adopting it, because
several record payloads when asked to be verbose. And this is a prohibition enforced by review
rather than by a gate — which is why it is an ADR with a review trigger rather than a comment.

## Review trigger

**Any proposal to add request logging, payload capture, or distributed tracing** to the scan
point services. The question is not whether the proposed layer is careful, but whether it
renders bodies at all; if it does, it is out of scope of this decision and needs this ADR
amended. Also revisit if protobuf-go ever honours `debug_redact` in its encoding path, which
would change what a reflective renderer produces and is worth re-verifying at each upgrade.
