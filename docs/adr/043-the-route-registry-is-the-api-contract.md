# ADR-043: The route registry is the API contract, and the OpenAPI document is emitted from it

**Status:** Accepted
**Date:** 2026-09-03

## Context

The operator API needs a machine-readable description. Clients are generated from it, the web
UI is written against it, and an integrator reads it to find out what their account needs to
hold before they can call anything.

There are three ways to get one, and the choice is not really about tooling.

**Hand-written.** A `openapi.yaml` in the repository. It describes what somebody believed the
API did on the day they wrote it, and nothing checks the belief.

**Annotations.** swaggo-style comments above each handler, scanned at build time. This is the
obvious answer and it is what most Go services do.

**Emitted from a value the server itself uses.** One declaration per endpoint, which is
simultaneously what the mux dispatches on, what the middleware enforces, and what the document
is rendered from.

ADR-025 says to buy commodity infrastructure rather than build it, and a reader arriving at
this package will reasonably ask why the third option is not a violation of it.

## Decision

**Each endpoint is declared once, as a `Route` value in `internal/control/api`, and the OpenAPI
document is emitted from those values.** No annotations, no hand-maintained spec file, no
generator that reads comments.

A `Route` carries the method, the path, an `Access` (public, session, or a named `Permission`),
the request and response types, and the handler. `Registry.Register` refuses — by panicking at
startup, because registration happens once from a fixed list — a route that declares no
`Access`, names a permission outside the closed set, states a permission its `Access` will not
enforce, or has no summary to put in the document.

`Server.mount` builds the middleware chain **per route, from that route's own declaration**,
and the handler is referenced nowhere else. So there is no path to a handler except through the
middleware built from its `Access`, and no way for the declared authorisation to differ from the
enforced one.

**The ADR-025 tension is real and is resolved by what the boundary actually says.** That ADR
draws its line between *analysis* — the thing this product is for, which we build — and
*commodity infrastructure*, which we buy. A spec emitter is neither. It is a consistency
mechanism for our own contract, in the same category as `internal/protocol`'s conformance tests
and `internal/scope/scopetest`'s shared decision table: code whose entire purpose is to stop two
descriptions of the same thing from disagreeing.

The specific failure being prevented is a route whose declared permission and enforced
permission differ. **An annotation cannot prevent it, because nothing reads an annotation at
runtime.** A comment saying `@Security scan.create` above a handler that checks `scan.read` is a
comment that is wrong, and it will be wrong in the direction of the document promising more
protection than exists — because the person who changed the check is the person who did not
think about the comment. Here the two cannot disagree, since there is only one of them.

**Do not simplify this to annotations later.** The registry is deliberately small; it does not
implement all of OpenAPI and does not try to. A shape it cannot express is a reason to extend
the emitter, not a reason to hand-write around it.

## Alternatives considered

**swaggo, or another annotation scanner.** Mature, widely used, and it produces a better
document than this emitter does — it handles more of the specification, and it is somebody
else's maintenance burden. Rejected on the one property that matters here: annotations are
hand-maintained comments that drift from the handler above them, and the drift is invisible in
review because a diff that changes a permission check does not show the comment fifteen lines
up. Every other advantage is real; none of them is about correctness of the security-relevant
half.

**oapi-codegen, spec-first.** Write the OpenAPI document, generate the server interfaces from
it, and the compiler enforces that every operation has a handler. This is a genuinely good
arrangement and the strongest alternative. Rejected for what it does *not* cover: it makes the
document authoritative about paths and schemas, which is most of an API — and says nothing about
authorisation, which is the part of this API most worth being right about. `x-` extensions are
untyped and generate nothing, so the permission would still be enforced by hand-written
middleware whose agreement with the document nothing checks. It solves the half we are less
worried about.

**A hand-written openapi.yaml.** Full control of the document, no tooling. Rejected without much
deliberation: it is the annotation problem with a longer distance between the two copies.

**No machine-readable document at all.** Serve the API, document it in prose. Rejected because
the web UI and the CLI are both clients of this surface and both want generated types, and
because an integrator with no document asks support instead — which is a worse version of the
same information with a person in the loop.

## Consequences

**A route cannot be served with an authorisation its document does not state.** That is the
property this decision buys, and it is asserted directly:
`TestTheDocumentDescribesEveryRoute` compares the emitted permission against the enforced one
for every route.

**A new route is unreachable until somebody decides who may reach it.** `AccessUndeclared` is the
zero value and always a registration error, so a route added without that decision stops the
process at startup rather than quietly becoming public. `TestEveryRouteDeclaresWhoMayReachIt`
additionally lists every public route by name, so adding one requires editing a test that says
why.

**The emitter is ours to maintain**, and it will need extending. It covers structs, slices,
pointers, maps, times and the scalar kinds — the shapes this API uses. It does not do `oneOf`,
discriminated unions, or `$ref` cycles beyond the self-reference guard. Each of those is a
half-day when it is first needed, which is the cost being accepted.

**The document is emitted per request rather than written to a file.** It is small and cheap,
and a file would be a second copy that can be stale. `TestTheDocumentIsStable` asserts byte
stability across renders, because a document whose key order moved between two identical
requests would produce a diff in every client's vendored copy for no reason.

**Nothing in the document names a tenant, and a test enforces that.** The tenant is resolved
from the request host (ADR-041), so a schema carrying a `tenant_id` would be a schema a client
fills in — and `DisallowUnknownFields` turns such a body into a 400 rather than silently
ignoring the field.

## Review trigger

A second HTTP surface — webhooks, a public findings API, anything served to something other than
an operator. The registry assumes one authorisation model (a session and a permission), and a
second surface with a different one (a signed webhook, a machine token with scopes) means either
extending `Access` or accepting that the mechanism covers one surface and not the other. Also
revisit if the emitter's gaps start being worked around in handler code rather than closed in
the emitter, which is the shape of this decision quietly reverting.
