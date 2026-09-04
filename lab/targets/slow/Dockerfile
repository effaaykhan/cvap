# See main.go for why this target exists and why two simpler versions of it did
# not work.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY main.go .
RUN go mod init fragile >/dev/null && CGO_ENABLED=0 go build -o /fragile .

FROM alpine:3.20
COPY --from=build /fragile /fragile
ENTRYPOINT ["/fragile"]
