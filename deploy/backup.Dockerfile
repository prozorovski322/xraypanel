# The backup image: the backup tool on top of the official PostgreSQL image, for its
# pg_dump and pg_restore.
#
# The major version is the server's. pg_dump refuses a newer server than itself, and a
# restore of a dump from a newer pg_dump is not guaranteed; keeping both on 16 means
# neither can happen quietly. Raising the server's major means raising this one with it.
#
# Build:
#   docker build -f deploy/backup.Dockerfile -t xraypanel-backup .

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
    -o /out/backup ./cmd/backup

FROM postgres:16-alpine

COPY --from=build /out/backup /usr/local/bin/backup

# The directory exists in the image, owned by the unprivileged postgres user, so that a
# named volume mounted over it starts with that ownership and no root is needed to write.
RUN mkdir -p /backups && chown postgres:postgres /backups && chmod 700 /backups

USER postgres

ENV BACKUP_DIR=/backups

VOLUME ["/backups"]

# Healthy means the newest dump is younger than two intervals. The start period covers the
# first backup, which runs as soon as the container starts on an empty volume.
HEALTHCHECK --interval=5m --timeout=10s --start-period=30m --retries=1 \
    CMD ["/usr/local/bin/backup", "health"]

# The base image's entrypoint would start a PostgreSQL server; this container is a client.
ENTRYPOINT ["/usr/local/bin/backup"]
CMD ["run"]
