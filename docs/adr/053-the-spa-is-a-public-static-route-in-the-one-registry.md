# ADR-053: The operator SPA is a public static route in the one registry, and its client is a third registry

**Status:** Accepted
**Date:** 2026-09-05

## Context

Session 19 builds the operator UI (execution-plan §2's week 7) over the read API session 18
added. Session 18's plan already settled that the single-page app is served **same-origin by
`cvap-core`** rather than from a separate static host — that is not relitigated here. What this
ADR records is how that serving fits the two invariants the API surface already has, and the
one new registry the UI introduces, because each had an obvious cheaper answer that breaks a
property the codebase relies on.

Three questions:

1. ADR-043 makes each endpoint a single `Route` value that is at once the mux dispatch, the
   enforced middleware, and the emitted OpenAPI operation — "they cannot disagree because there
   is only one of them." Its review trigger names **"a second HTTP surface"** as the thing that
   would break the one-registry guarantee. A SPA needs `GET /` and a catch-all for client-side
   routes. Is that a second surface?
2. ADR-041 reads the tenant from the request Host and from nothing else, before any handler
   runs. The SPA's static assets are the same bytes for every tenant. What access class and
   tenant treatment does a route that serves identical bytes to everyone take?
3. The TypeScript client is generated from the OpenAPI the Route values emit. That makes it a
   derived artifact of the route registry — the same relationship `gen/` has to `proto/`.

## Decision

### The SPA is served through the one registry, as `Route` values — not a second surface

`registerSPA()` adds the SPA the same way every other endpoint is added: as `Route` values
mounted by `Server.mount`, dispatched by the same mux, carrying the same middleware chain built
from their own declaration. There is no second `http.Handler`, no separate `ServeMux`, no
file-server bolted on beside the API. The catch-all that lets client-side routes deep-link is
one registered route with the registry's own precedence, not a fallback wired outside it.

This is the direct answer to ADR-043's "second HTTP surface" trigger: **the SPA did not create
one.** Serving static files through a hand-rolled second mux would have — it would be a set of
paths the OpenAPI document does not describe, the middleware does not see, and the route tests
do not enumerate, which is exactly the divergence the single registry exists to prevent. The
constraint held; the emitter and the tests were extended to keep it holding (below), rather than
the surface being split to avoid extending them.

### The SPA routes are `AccessPublic`, and carry no tenant

The static routes are declared `AccessPublic`: the HTML, JS and CSS bundle is identical for
every tenant and every user, authenticated or not. There is nothing tenant-scoped in the bytes,
so there is nothing for `resolveTenant` to scope — the app shell loads, and then it calls
`GET /v1/auth/session`, which runs behind the full tenant-and-auth chain like every other `/v1`
route. **The authority boundary is the API, not the page.** A viewer who loads the SPA with no
session sees the login screen because the data calls return `401`, not because the page was
withheld; the page carries no secrets to withhold. This is the same reasoning that makes a login
form public: refusing to serve the shell would leak nothing and protect nothing.

The RBAC the UI reflects is a courtesy over server-side enforcement, never a substitute for it.
A hidden nav item or a disabled button is a convenience; the check that matters already ran in
the middleware the `Route` declared. Specifically, the `export_all` control **degrades honestly**
for a caller without the permission — a disabled control that names the missing permission,
never an absent option that pretends the capability does not exist — because the UI must not be
the only thing between a viewer and an operator action. (This is a UI property, enforced by the
server; it is recorded here because it is the same public-shell/authoritative-API split.)

### Static routes are served but excluded from the OpenAPI operations

A `Route` gains a `Static bool`. A static route is mounted and enforced like any other, but the
OpenAPI emitter skips it (`if r.Static { continue }`): `GET /` and the catch-all are not API
operations, they have no request or response schema a client generator could use, and emitting
them as operations would put junk paths in the document and, worse, in the generated client.

The emitter is what was extended, **not** the registry worked around — which is ADR-043's own
rule for a shape the emitter cannot yet express ("a reason to extend the emitter, not to
hand-write around it"). Two route tests hold the new field honest in both directions:
`TestTheDocumentDescribesEveryRoute` skips static routes, and
`TestStaticRoutesAreExcludedFromTheDocument` asserts they are absent — so a non-static route
missing from the document still fails, and a static route leaking into it fails too.

### The generated client is a third registry, held to proto-verify's rule

The TypeScript types the client is built on (`web/src/api/schema.ts`) are generated by
`openapi-typescript` from the OpenAPI the Route values emit (`cmd/cvap-openapi`, DB-free). That
makes the checked-in client a **third registry** that must agree with the route registry and the
CI workflow — the same relationship `gen/` has to `proto/`, and it gets the same treatment:

- `make ui-types` regenerates the file in place; `make ui-verify` regenerates into a temp file
  and **diffs against the committed one, failing on any difference** — proto-verify's exact
  shape, so `make ci` never mutates the working tree.
- The CI `web` job runs `ui-verify`, so a route added or reshaped without regenerating the
  client **fails the build**, the way a `proto/` change without `make proto-gen` fails
  proto-verify. `check_ci_parity.py` requires the job by name, so the gate cannot be deleted from
  CI while surviving in `make ci`.

A comment asking the next author to regenerate would be the annotation ADR-043 already rejected
for permissions: nothing reads it at runtime. The diff does.

## Alternatives considered

**A separate static file server (second mux/handler).** Cheapest, and the reflex. Rejected: it
is precisely the "second HTTP surface" ADR-043's review trigger names — paths outside the one
registry, undescribed by OpenAPI, unseen by the middleware chain, unenumerated by the route
tests. The whole value of the single registry is that dispatch, enforcement and documentation
cannot disagree; a second surface reintroduces the disagreement for the largest set of paths in
the app.

**Serve the SPA from a separate origin / CDN.** Would force CORS on every `/v1` call and move
the session cookie to a cross-site posture. Rejected — and explicitly out of scope: same-origin
was settled in session 18's plan, and "do not add CORS" was a standing constraint. Same-origin
keeps the cookie host-only and `SameSite=Lax` meaningful.

**Give the SPA routes a real `Access` class other than public.** There is no tenant or user
distinction in the bytes, so any non-public class would either be enforced against nothing or
withhold a shell that carries no secrets. Rejected: it dresses a public asset as protected and
invites the reader to think the page is the boundary. The API is the boundary.

**Emit the static routes as OpenAPI operations.** One fewer special case in the emitter.
Rejected: they have no schema, so the generated client would carry operations for `GET /` and a
catch-all that return HTML — noise at best, a mis-typed call at worst. Excluding them is what
keeps the third registry a faithful image of the API.

**Hand-write or hand-maintain the TypeScript types.** Rejected for the same reason `gen/` is not
hand-edited: a hand-kept client drifts from the contract silently, and the drift is found by a
runtime type error in a browser rather than by a build gate. Generation plus a diff gate makes
the drift a failed CI job.

## Consequences

The SPA is one more set of routes in the same registry, enforced by the same chain, and the
OpenAPI document still describes exactly the API — no more, no less — because static routes are
excluded by a field the tests hold in both directions. The client is regenerated and diffed in
CI, so the route registry, the workflow, and the generated client are three registries kept in
agreement mechanically, not by anyone remembering.

The `embedui` build tag is the seam between "API only" and "API with the SPA embedded":
`go build ./...` compiles the stub and the binary serves a not-built placeholder; `go build
-tags embedui` embeds `web/dist`. `make embedui-build` is the only build that compiles the
`//go:build embedui` files and links the bundle, so a broken embed path fails in CI's `web` job
and nowhere else. The default build staying SPA-free keeps `go build ./...` independent of the
Node toolchain.

The exposure view surfaces a real data limitation rather than papering over it: it shows the
zone-derived count and states, in the UI, that `internet_reachable` is not yet written, so the
page implies no reachability judgement the data cannot support. Recorded here because it is the
same honesty rule as the `export_all` degradation — the UI presents what the data is, not what
would look finished.

## Review trigger

A second thing that wants serving outside the API — a metrics endpoint, a health probe, a
webhook receiver — that is reached for as its own `http.Handler`. The answer is the same as it
was here: add it as a `Route`, extend the emitter if its shape is new, and keep the one
registry. If a genuine second surface ever becomes unavoidable (a different port, a different
auth model that cannot be a `Route`), that is the point to revisit ADR-043's guarantee
deliberately, not to let it erode one handler at a time.
