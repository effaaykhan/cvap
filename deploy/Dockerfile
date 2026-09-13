# Single-node CVAP image: the control plane (with the operator SPA embedded) and
# its CLI in one binary set.
#
# Three stages. The web stage builds the Vite SPA; the Go stage compiles static
# binaries and embeds that SPA into cvap-core (-tags embedui); the runtime is
# distroless static (no shell, no package manager, nonroot), because Core holds a
# map of a customer's weaknesses and credentials to their estate — the smaller
# the attack surface of the thing that holds that, the better (architecture-v2
# §18.3).
#
# cvap-core embeds the IANA timezone database (a blank import in its main), so
# the static base carrying no /usr/share/zoneinfo is correct rather than a gap.

# ---- Stage 1: the operator SPA ----------------------------------------------
# web/dist is gitignored, so a clean checkout has none: the image must BUILD it,
# not rely on a host-built copy. Without this stage cvap-core links its stub and
# serves a 503 "UI not built into this binary" page instead of the screens.
FROM node:22-bookworm-slim AS web
WORKDIR /web
# Lockfile first, so a source-only change does not re-run npm ci.
COPY internal/control/api/web/package.json internal/control/api/web/package-lock.json ./
RUN npm ci
COPY internal/control/api/web/ ./
RUN npx --no-install vite build

# ---- Stage 2: the Go binaries -----------------------------------------------
FROM golang:1.26 AS build
WORKDIR /src

# Modules first, so a source-only change does not re-download the graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The SPA built above, placed where `//go:embed all:web/dist` (spa_embed.go)
# expects it. The path is relative to internal/control/api/.
COPY --from=web /web/dist ./internal/control/api/web/dist

# CGO off for a static binary the distroless base can run. Trimpath and no DWARF
# keep the image small and the build reproducible. VERSION is stamped in.
ARG VERSION=dev
ENV CGO_ENABLED=0
# cvap-core is built with -tags embedui so the SPA is served from the binary; the
# others have no UI and are built plain.
RUN go build -trimpath -tags embedui -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-core ./cmd/cvap-core \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-cli    ./cmd/cvap-cli \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-noop        ./cmd/cvap-engine-noop \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-discovery   ./cmd/cvap-engine-discovery \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-fingerprint ./cmd/cvap-engine-fingerprint \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-credhost    ./cmd/cvap-engine-credhost \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-scanpoint ./cmd/cvap-scanpoint

# ---- Stage 3: the runtime ---------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
# cvap-core is the default; the compose and the runbook override it for the CLI
# one-shots (bootstrap, enroll-token) and for a scan point.
ENTRYPOINT ["/usr/local/bin/cvap-core"]
