# The panel image: one static binary, run as an unprivileged user.
#
# Build:
#   docker build -f deploy/panel.Dockerfile -t xraypanel-panel .
#
# The same image runs the server ("serve", the default) and the one-shot "migrate" the
# production compose file starts before it.

# ------------------------------------------------------------------ build

# The builder runs on the build machine's own architecture and cross-compiles, which is
# much faster than building arm64 under emulation. Go needs nothing but GOARCH for that.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/panel ./cmd/panel

# ------------------------------------------------------------------ image

FROM alpine:3.22

# ca-certificates for outgoing webhooks over HTTPS; tzdata because BILLING_TIMEZONE is an
# IANA zone name and has to resolve to something.
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 panel \
 && adduser -S -D -H -u 10001 -G panel panel

COPY --from=build /out/panel /usr/local/bin/panel

# Nothing in the panel needs root: its ports are above 1024 and its state is in Postgres.
USER 10001:10001

EXPOSE 8080 8443

# Liveness only. /healthz does not touch the database on purpose: a database blip should
# not get the panel restarted, which would also drop every node's control stream.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/panel"]
CMD ["serve"]
