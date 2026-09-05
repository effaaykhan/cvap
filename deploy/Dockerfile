# Single-node CVAP image: the control plane and its CLI in one binary set.
#
# Multi-stage. The builder compiles static binaries; the runtime is distroless
# static (no shell, no package manager, nonroot), because Core holds a map of a
# customer's weaknesses and credentials to their estate — the smaller the
# attack surface of the thing that holds that, the better (architecture-v2 §18.3).
#
# cvap-core embeds the IANA timezone database (a blank import in its main), so
# the static base carrying no /usr/share/zoneinfo is correct rather than a gap:
# a named maintenance window resolves from the embedded copy.

FROM golang:1.25 AS build
WORKDIR /src

# Modules first, so a source-only change does not re-download the graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off for a static binary the distroless base can run. Trimpath and no DWARF
# keep the image small and the build reproducible. VERSION is stamped in.
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-core   ./cmd/cvap-core \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-cli    ./cmd/cvap-cli \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-noop        ./cmd/cvap-engine-noop \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-discovery   ./cmd/cvap-engine-discovery \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-engine-fingerprint ./cmd/cvap-engine-fingerprint \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cvap-scanpoint ./cmd/cvap-scanpoint

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
# cvap-core is the default; the compose and the runbook override it for the CLI
# one-shots (bootstrap, enroll-token) and for a scan point.
ENTRYPOINT ["/usr/local/bin/cvap-core"]
