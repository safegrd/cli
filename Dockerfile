# The SafeGrd CLI image: the safegrd binary with the database dump clients it
# calls, and a PostgreSQL server for sandbox drills. pg_dump has to be at least
# as new as the Postgres server it reads, and a newer pg_dump reads every older
# server, so the image carries the newest client and its tag says which:
# ghcr.io/safegrd/cli:<version>-pg18. The server (initdb and postgres) is what
# a drill loads the backup into on a plan that sells sandbox drills; without
# it every drill a container runs is in memory. It restores into a throwaway
# cluster under /home/safegrd/.safegrd, so the volume mounted there needs room
# for the largest database the host backs up.
#
#   docker build --build-arg VERSION=0.4.0 -t safegrd/cli .

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.24

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/safegrd/cli/internal/cli.Version=${VERSION} -X github.com/safegrd/cli/internal/cli.Commit=${COMMIT} -X github.com/safegrd/cli/internal/cli.Date=${BUILD_DATE}" \
      -o /out/safegrd ./cmd/safegrd

FROM alpine:${ALPINE_VERSION}
ARG PG_MAJOR=18
# pg_dump and psql for Postgres, mysqldump for MySQL and MariaDB, mongodump for
# MongoDB, and the Postgres server for sandbox drills (Alpine puts it under
# /usr/libexec/postgresql<major>, which the CLI searches). SQLite needs
# nothing: the CLI reads it directly.
RUN apk add --no-cache ca-certificates tzdata \
      postgresql${PG_MAJOR}-client postgresql${PG_MAJOR} mariadb-client mongodb-tools \
 && addgroup -S -g 10001 safegrd \
 && adduser -S -u 10001 -G safegrd -h /home/safegrd safegrd \
 && install -d -o safegrd -g safegrd -m 0700 /home/safegrd/.safegrd
COPY --from=build /out/safegrd /usr/local/bin/safegrd

# The config, the key and the daemon's state live under /home/safegrd/.safegrd.
# The directory exists in the image, owned by uid 10001, so a named volume
# mounted there starts out writable by it. A config or key mounted from
# elsewhere has to be owned by uid 10001 with mode 0600: the CLI refuses one
# that group or others can read.
USER safegrd
WORKDIR /home/safegrd
ENTRYPOINT ["safegrd"]
CMD ["daemon", "run"]

LABEL org.opencontainers.image.source="https://github.com/safegrd/cli" \
      org.opencontainers.image.description="SafeGrd CLI: encrypted, locked backups of PostgreSQL, MySQL, MongoDB, SQLite, files and mailboxes, and the drills that prove they restore" \
      org.opencontainers.image.licenses="BUSL-1.1"
