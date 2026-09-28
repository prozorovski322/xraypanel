# The node image: the agent as PID 1, xray-core as its child.
#
# One image with both, rather than two containers, because the agent's whole job is to
# supervise that specific process: start it, wait for it to serve, notice it die, restart
# it, and stop it. Splitting them would mean the supervisor talking to a container
# runtime, which is a second thing to get wrong on every node.
#
# Build:
#   docker build -f deploy/node.Dockerfile --build-arg XRAY_VERSION=v26.3.27 -t xraypanel-node .

# ------------------------------------------------------------------ build the agent

FROM golang:1.26-alpine AS agent

WORKDIR /src

# Dependencies first, so a code change does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none

# CGO off so the binary runs on a distroless-style base with no libc surprises.
ENV CGO_ENABLED=0
RUN go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/nodeagent ./cmd/nodeagent

# ------------------------------------------------------------------- fetch xray-core

FROM alpine:3.22 AS xray

# Pinned by the caller. An unpinned core means two nodes built a week apart run different
# versions, and a traffic-accounting or handshake difference between them is very hard to
# attribute later.
ARG XRAY_VERSION=v26.3.27
ARG TARGETARCH=amd64

RUN apk add --no-cache curl unzip ca-certificates

WORKDIR /tmp/xray
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) asset="Xray-linux-64.zip" ;; \
        arm64) asset="Xray-linux-arm64-v8a.zip" ;; \
        *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"; \
    curl -fsSL -o xray.zip "${base}/${asset}"; \
    curl -fsSL -o xray.zip.dgst "${base}/${asset}.dgst"; \
    # Verified against the digest the release publishes, before anything is unpacked.
    # A node runs this binary with network privileges; taking it on trust from a
    # download would make the build the weakest link in the whole system.
    local_sum="$(sha256sum xray.zip | awk '{print $1}')"; \
    grep -qi "${local_sum}" xray.zip.dgst || { \
        echo "checksum mismatch for Xray ${XRAY_VERSION}" >&2; \
        echo "expected one of:" >&2; cat xray.zip.dgst >&2; \
        echo "got: ${local_sum}" >&2; \
        exit 1; \
    }; \
    unzip -q xray.zip -d /out; \
    chmod +x /out/xray; \
    /out/xray version

# ------------------------------------------------------------------------ the image

FROM alpine:3.22

# ca-certificates for the agent's TLS to the panel; tzdata so timestamps in the log are
# not a guess.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=agent /out/nodeagent /usr/local/bin/nodeagent
COPY --from=xray /out/xray /usr/local/bin/xray
COPY --from=xray /out/geoip.dat /out/geosite.dat /usr/local/share/xray/

# Identity, configuration and local state. A volume, because losing it means the node has
# to be enrolled again by hand.
RUN mkdir -p /var/lib/xraypanel-node && chmod 700 /var/lib/xraypanel-node
VOLUME ["/var/lib/xraypanel-node"]

ENV XRAY_LOCATION_ASSET=/usr/local/share/xray \
    NODE_DATA_DIR=/var/lib/xraypanel-node \
    NODE_XRAY_BINARY=/usr/local/bin/xray

# Runs as root deliberately. The node serves inbounds on whatever ports an operator
# configures, including ports below 1024, and it is expected to run with
# network_mode: host on a machine dedicated to being an exit node. Dropping privileges
# here would only move the problem to a capability an operator has to remember to grant.
USER root

# No health check: liveness is the control stream the panel already watches, and a
# container-level probe would be a second, disagreeing opinion about whether the node is
# working.

ENTRYPOINT ["/usr/local/bin/nodeagent"]
CMD ["run"]
