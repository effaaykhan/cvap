# ADR-038: A secret field is a func of a type that can be zeroised

**Status:** Accepted
**Date:** 2026-09-03

**Supersedes ADR-035.**

## Context

ADR-035 requires a hand-written type holding credential material to store it in a
`func() string` field rather than a `string` field, because a func value has no rendering —
reflection prints an address at every verb, including inside an unexported field of another
struct, which is the one position where no method of ours can run. That reasoning is right and
this ADR keeps it.

The concrete type is not. ADR-035 was written for `enrollment.PlaintextToken`: a value that
Core hashes, compares against a stored digest and drops inside one function call. Nothing ever
asked it to erase itself, so `string` cost nothing.

The scan point runtime's credential holder is the case ADR-035 did not anticipate. ADR-020
requires credential material to be **zeroised on job completion, lease loss, or abort**, and it
lives for the duration of a job — minutes, across goroutines, in a process whose host is
assumed compromised. A Go `string` cannot be zeroised at all: it is immutable, its backing
array is not addressable through any supported API, and overwriting the variable only drops one
reference to bytes the garbage collector will free whenever it likes. Under ADR-035's literal
wording the invariant ADR-020 states as a requirement is not implementable.

The wire type is already `bytes`: `CredentialGrant.material` is `bytes material`, so
`func() string` also forces a conversion whose only effect is to make an immutable copy of the
secret and put it beyond reach.

## Decision

**A hand-written type holding secret material stores it in a func-typed field, and where the
secret outlives a single call the func's return type must be one that can be erased in place.**

- `func() []byte` for anything with a lifetime — a credential held for a job, a session key,
  anything ADR-020 requires zeroising. The holder owns the only copy, `Reveal()` is the sole
  accessor, and `Zeroise()` overwrites the backing array and drops the closure.
- `func() string` remains correct for a value that is compared and discarded within one call,
  which is what ADR-035 was written for and what `PlaintextToken` still is.

The control is unchanged and is the reason both forms are funcs: **the field type is what makes
the value unprintable.** `String()`, `GoString()`, `LogValue()` and `MarshalJSON()` returning a
redacted form all stay, as hygiene on top of the field type and as the thing that catches
someone changing the field back to a bare `string` or `[]byte` — which is the likely future
mistake, and the one ADR-035's test enumeration exists to fail on.

Every new secret-holding type repeats that enumeration: every verb, in value, pointer, slice,
map and unexported-field positions. `internal/control/enrollment/token_test.go` is the pattern;
`internal/scanpoint/creds_test.go` is the second instance.

Zeroisation is **best-effort and must be documented as such** wherever it is claimed. A
`[]byte` the holder owns can be overwritten; a copy made by anything the value was passed to
cannot, and a garbage collector that moved the allocation before the overwrite leaves the
original bytes wherever they were. This is why ADR-020 also disables core dumps on engine
processes and why credentials stop at the runtime rather than travelling to engines: the
erasure is one layer of a defence, not the defence.

## Alternatives considered

**Keep `func() string` and accept that zeroisation is nominal.** The smallest change, and it
preserves one rule instead of two. Rejected: it makes ADR-020's "zeroised on job completion,
lease loss, or abort" a sentence no code can honour, and an invariant that cannot be
implemented is one that gets asserted anyway. A `credentials_zeroised` attestation on
`JobTerminal` that was structurally incapable of being true would be worse than no field —
Core raises an audit event when that flag is absent, so the flag would become a lie the audit
log records as a fact.

**Amend ADR-035 in place rather than superseding it.** Rejected on the repository's own rule:
accepted decisions are superseded, not edited, and `protect-contracts.py` enforces it. ADR-029
is the exception and says so in its own text, because it is an enumeration that grows; ADR-035
is a decision, and a decision that changes gets a new record so the reasoning that changed is
visible rather than overwritten.

**Use a `[N]byte` array or an off-heap allocation with `mlock`.** Stronger: an array is
addressable and never reallocated by the collector, and `mlock` keeps it out of swap. Rejected
for now as disproportionate — it fixes the GC-moved-the-allocation gap while the same process
still holds the plaintext in whatever buffers the TLS stack and protobuf decoder used to
receive it, which is the larger hole and is not addressable at this layer. Revisit if the scan
point ever holds long-lived material rather than per-job grants.

**Require zeroisation of every secret type, including `PlaintextToken`.** Uniform, and it
would remove the judgement call. Rejected: the token's value is a bearer credential Core
receives, hashes and drops, and giving it a `Zeroise()` invites the belief that calling it
erased the token — when the same bytes are still in the gRPC receive buffer, the protobuf
message and whatever the caller kept. A method that suggests a property it cannot deliver is
worse than its absence.

## Consequences

Two forms exist where there was one, and the rule for choosing is a question about lifetime
rather than a preference: does the secret outlive the call that received it. That question has
an answer at every site, which is what keeps this from becoming a style debate.

`internal/scanpoint` can implement ADR-020's zeroisation requirement, and
`JobTerminal.credentials_zeroised` can be true for a reason rather than by assertion.

The cost is that "secrets are `func() string`" — a rule short enough to remember — becomes a
rule with a condition attached. The mitigation is that both forms fail the same way if someone
writes a bare field, and both are covered by the same test enumeration.

## Review trigger

A secret that must outlive a process, or one large enough that a copy in a TLS buffer is the
dominant exposure rather than an equal one. Either would mean the erasure boundary is in the
wrong place and belongs closer to the transport than to the holder.
