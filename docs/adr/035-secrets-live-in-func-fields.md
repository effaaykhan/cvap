# ADR-035: A hand-written type holding a secret stores it in a `func() string`

**Status:** Accepted
**Date:** 2026-09-01

## Context

`internal/logging/CLAUDE.md` requires a hand-written type holding credential material to
implement `String()`, `GoString()`, `LogValue()` and `MarshalJSON()` returning a redacted
form. `PlaintextToken` (ADR-018's enrollment token) does all four. That is necessary and it is
not sufficient, for a reason nothing in the toolchain reports.

**`fmt` calls no method at all when the value sits in an unexported field of another struct.**
`reflect.Value.CanInterface` is false there, so `fmt` cannot obtain an interface to check for
`Stringer`, `GoStringer` or `Formatter`, and renders the underlying value directly. Every
method-based defence is skipped at once — not one of them, all of them — and the shape that
triggers it is ordinary: a handler or an issuer caching a token in a private field.

A second, smaller gap sits next to it: `fmt.handleMethods` consults `Stringer` only for
`%v %s %q %x %X`. Under `%d`, `%b`, `%c`, `%e` and the rest it falls through to reflection.
`go vet` catches that for a constant format string and not for a computed one.

Neither is visible to `.github/scripts/check_secret_logging.py`, which is a lexical check over
Go source: nothing at the leak site names a secret type. `go vet` does not see the first case
at all. Both were found by a security review widening a test to enumerate verbs and positions,
not by anyone reasoning about `fmt`.

This is the same family as ADR-034 — renderings the source-level gate cannot see — but a
different mechanism. ADR-034 is about a reflective layer we choose to add. This is about `fmt`
bypassing methods we did add.

## Decision

**A hand-written type holding credential material stores it in a `func() string` field, never
a `string` field.** The accessor is `Reveal()`, which calls it. The redacting methods stay —
they are what makes direct rendering legible — but they are no longer what makes it safe.

A func value has no rendering. Reflection prints it as an address at every verb, in every
position, including an unexported field of another struct, which is the one position where no
method of ours can run.

Measured on Go 1.25 rather than reasoned about, because the obvious reading is the wrong way
round:

| | `%d` | inside an unexported field, `%v` |
|---|---|---|
| `string` field | `{%!d(string=SECRET)}` | `{{SECRET}}` |
| `func() string` field | `{4824512}` | `{{0x499dc0}}` |

So the **field type is the control**, and `Format()` is hygiene on top of it: with the func
field every verb is already safe, and `Format` only makes the output say `[REDACTED]` instead
of an address. Both stay — `Format` is also what catches someone changing the field back to a
string, which is the likely future mistake.

`internal/control/enrollment/token_test.go` enumerates every verb, in value, pointer, slice,
map and unexported-field positions. That enumeration is the test that found both gaps, and it
is the pattern for the next such type.

## Alternatives considered

**Rely on the four redacting methods.** What we had, and what every style guide would tell you
is enough. Rejected on measurement: it is exactly right for a value rendered directly and
exactly wrong for one inside an unexported field, and the second is not an unusual position.

**Forbid holding a secret in a struct field at all — pass it as a bare parameter.** Genuinely
strong, and it dissolves the problem rather than fixing it. Rejected because it does not
survive contact: `IssuedToken` has to return a token alongside its id and expiry, and a
caller that must thread a bare string through four call sites will put it in a struct anyway,
with no type to defend it.

**A `[]byte` field.** Renders as numbers rather than text under `%v` — `[99 118 97 112 ...]`.
Rejected: it is obfuscation, not redaction. `%s` on a `[]byte` inside an unexported field
prints the secret verbatim, and a reader with the bytes has the token.

**Encrypt the field in memory and decrypt in `Reveal()`.** Defeats reflection completely.
Rejected as disproportionate: the key would sit in the same process, so it defends against
accidental rendering and nothing else — which the func field already does, for free, with no
key to manage.

**A linter or a `go vet` analyser detecting the shape.** See the gate section below; it was
attempted and produces false positives on the common case.

## Consequences

The type is slightly awkward to construct — a closure rather than an assignment — and that
awkwardness is confined to one constructor per type. `PlaintextToken` is no longer comparable
with `==`, since a struct containing a func is not comparable; nothing needed that, and
comparing two secrets for equality is not an operation this codebase should make easy.

The rule applies to every future hand-written secret type: credential material delivered to a
scan point (ADR-020), any vault token, any signing key held as bytes. Each needs the same
field type and the same verb-enumeration test.

The honest limit: this defends against *accidental* rendering. Anything that can call
`Reveal()` can still print the result, which is why `check_secret_logging.py` flags `.Reveal()`
inside a formatting call and why the method is named to be conspicuous.

## The gate: attempted, and deliberately not shipped

The detectable shape is "a struct field whose type is a known secret-bearing type and whose
name is lowercase". It was implemented as a prototype and run against this repository, and the
result is why it is not shipped:

```
internal/control/enrollment/token_test.go:128: unexported field tok of type PlaintextToken

1 hit(s)
```

**One hit, and it is the test that proves the shape is safe.** `privateHolder` in
`TestPlaintextTokenNeverRenders` exists precisely to hold a token in an unexported field and
assert nothing leaks. A check whose only finding is the code demonstrating correctness is not
a check; it is a false-positive generator with a 100% rate on the current tree.

The reason is structural, not a matter of tuning. The check sees the holder's field name and
type; it cannot see that `PlaintextToken`'s own field is a `func() string`. So it cannot
distinguish the shape this ADR mandates from the shape it forbids — and under this ADR,
holding a secret type in an unexported field is *correct*.

Making it useful would mean checking the *type's* field kinds rather than the holder's field
name — type resolution across packages, which is `go/types` and a different tool from
`check_secret_logging.py`'s lexical scan. Worth doing if hand-written secret types multiply;
not worth it for one type with an exhaustive test.

A check that fires on the correct shape trains people to add suppressions, and a gate people
suppress is worse than a documented rule. So this stays a rule with a test.

What the gate does cover, and does keep: `.Reveal()` reaching a formatting call
(`GO_SECRET_IDENTIFIERS`, rule 4), which is the one leak the type itself cannot prevent.

## Review trigger

**Any new hand-written type holding credential material** — it needs the func field and the
verb-enumeration test, not just the four methods.

**Any Go release that changes `fmt`'s treatment of unexported fields**, or that makes
`reflect` able to render func values as anything but an address. Both would invalidate the
measurement above, and the measurement is the whole argument. Re-run
`TestPlaintextTokenNeverRenders` against a new toolchain before assuming it still holds.
