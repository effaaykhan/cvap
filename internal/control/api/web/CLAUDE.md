# internal/control/api/web

The operator console. React + TypeScript, built by Vite, embedded into
`cvap-core` under the `embedui` build tag and served same-origin (ADR-053).

## Never hand-edit `src/api/schema.ts`

It is GENERATED from the Go route registry: `cmd/cvap-openapi` emits the OpenAPI
document from the `Route` values, and `openapi-typescript` turns it into types.
`make ui-verify` regenerates it and fails on any diff — session 19's note calls
it the THIRD registry that must agree, and it gets `gen/`'s treatment.

A shape you need that is not in `schema.ts` is a shape the server does not
serve. Ask for the route to change; do not widen the type to make the compiler
agree with a response the API never sends.

## The toolchain is not on this host

Node, npm and npx are not installed. Everything runs in the `node:20-alpine`
image already present on the box:

```bash
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
  -v /home/soc/cvap/internal/control/api/web:/w -w /w node:20-alpine <cmd>
```

`npm ci` once, then `npx --no-install vite build`, `npx --no-install tsc -b
--noEmit`, `npx --no-install vitest run`. Prefix docker with `sg docker -c` if
the shell predates the docker group membership.

## Run the whole gate, not the part you think is relevant

`make ui` is ui-verify, ui-typecheck, ui-test and embedui-build. The last one is
the only build that compiles the `//go:build embedui` files and links the bundle
into `cvap-core`, so a broken embed path fails there and nowhere else.

The gate skipped because "this change cannot trip it" is the one that trips it.
Four fields added to `HealthResponse` left `ui-verify` red and the typecheck
failing for two commits, because a store-layer change was judged unable to touch
the web client. It regenerated `schema.ts` and broke a Health fixture typed as
`Health`.

## Dev server

`vite dev` proxies `/v1` to `http://127.0.0.1:8080` — plain HTTP, so Core must
run with `CVAP_CORE_API_INSECURE=1`. The proxied Host resolves to `localhost`,
which must be a real `tenants.domain` row (ADR-041), so bootstrap the dev tenant
with `-domain localhost` or the login is refused with "host resolved to no
tenant".

## What the console must not assert

The UI renders what the scanner established, and says so when it established
little.

- A service row whose `identification_method` is `discovery` is a port that
  ANSWERED and nothing more. Render it "open, unidentified" — never as a product
  or a recognised service (ADR-103/104). `isSeenOnly` in `lib/console.ts` is the
  one place that decision lives; do not re-derive it per screen.
- A scan's results are read from observations, which are pruned (ADR-016). An
  older scan shows fewer and eventually none. The screen says that, because a
  result page that silently empties reads as data loss rather than retention.
- Confidence and provenance are shown, not hidden. "Apache 2.2.8 (banner, high)"
  is a claim with a source; "unknown" is a service seen, not a version
  confirmed.

## Permissions are reflected, never enforced

`has(session, perm)` decides whether to SHOW a control. The server ran the check
that matters. A hidden button is a courtesy; a 403 handled honestly is the
control.
