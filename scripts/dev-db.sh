#!/usr/bin/env bash
#
# Manage a local PostgreSQL cluster for development without Docker.
#
# The docker-compose path (`make dev-up`) is the primary one and the one CI uses.
# This script exists for machines where Docker is not available — installing
# Docker Desktop on Windows needs administrator rights, WSL2 and a reboot, which
# is a lot to demand before a developer can run the test suite.
#
# Usage:
#   scripts/dev-db.sh init     Create the cluster and the panel database
#   scripts/dev-db.sh start    Start the server
#   scripts/dev-db.sh stop     Stop the server
#   scripts/dev-db.sh status   Report whether it is accepting connections
#   scripts/dev-db.sh reset    Drop and recreate the database, then migrate
#   scripts/dev-db.sh psql     Open a psql shell
#
# Override the defaults with environment variables:
#   PGSQL_HOME  directory holding bin/postgres (default: platform guess)
#   PGDATA_DIR  cluster data directory
#   PGPORT      port to listen on (default 5432)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load .env the same way the Makefile does, so `reset` can run the migration with
# the same configuration the panel itself would use. A script that needs a
# different environment than the binary is a script that drifts.
if [ -f "${REPO_ROOT}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "${REPO_ROOT}/.env"
    set +a
fi

PGPORT="${PGPORT:-5432}"
PGUSER_DEV="${PGUSER_DEV:-panel}"
PGPASSWORD_DEV="${PGPASSWORD_DEV:-panel}"
PGDATABASE_DEV="${PGDATABASE_DEV:-panel}"

# The data directory must not live inside the repository. Beyond the obvious noise
# in git status, a project folder synced by OneDrive or Dropbox will corrupt a
# running cluster: the sync client rewrites files underneath the server.
default_state_dir() {
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) echo "${LOCALAPPDATA}/xraypanel-dev" ;;
        Darwin) echo "${HOME}/Library/Application Support/xraypanel-dev" ;;
        *) echo "${XDG_STATE_HOME:-$HOME/.local/state}/xraypanel-dev" ;;
    esac
}

STATE_DIR="$(default_state_dir)"
PGDATA_DIR="${PGDATA_DIR:-$STATE_DIR/pgdata}"
LOG_FILE="${STATE_DIR}/postgres.log"

default_pgsql_home() {
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) echo "${LOCALAPPDATA}/Programs/pgsql16/pgsql" ;;
        *) echo "/usr/lib/postgresql/16" ;;
    esac
}

PGSQL_HOME="${PGSQL_HOME:-$(default_pgsql_home)}"
PGBIN="${PGSQL_HOME}/bin"

die() {
    echo "error: $*" >&2
    exit 1
}

require_binaries() {
    for tool in initdb pg_ctl pg_isready psql createdb dropdb; do
        [ -x "${PGBIN}/${tool}" ] || [ -x "${PGBIN}/${tool}.exe" ] \
            || die "${tool} not found in ${PGBIN} (set PGSQL_HOME)"
    done
}

pg() {
    local tool="$1"
    shift
    "${PGBIN}/${tool}" "$@"
}

cmd_init() {
    require_binaries
    [ -f "${PGDATA_DIR}/PG_VERSION" ] && die "cluster already exists at ${PGDATA_DIR}"

    mkdir -p "${STATE_DIR}"
    local pwfile="${STATE_DIR}/.initpw"
    printf '%s' "${PGPASSWORD_DEV}" >"${pwfile}"
    chmod 600 "${pwfile}" 2>/dev/null || true

    # locale=C keeps ORDER BY deterministic regardless of the host locale, so a
    # test that passes here passes in CI.
    pg initdb -D "${PGDATA_DIR}" -U "${PGUSER_DEV}" --pwfile="${pwfile}" \
        -E UTF8 --locale=C -A scram-sha-256
    rm -f "${pwfile}"

    # Every timestamp the panel stores is UTC, and traffic buckets are keyed by UTC
    # hour. Pinning the server timezone keeps development identical to production
    # regardless of the host clock.
    cat >>"${PGDATA_DIR}/postgresql.conf" <<CONF

# --- xraypanel dev overrides ---
listen_addresses = '127.0.0.1'
port = ${PGPORT}
timezone = 'UTC'
log_timezone = 'UTC'
CONF

    cmd_start
    PGPASSWORD="${PGPASSWORD_DEV}" pg createdb -h 127.0.0.1 -p "${PGPORT}" \
        -U "${PGUSER_DEV}" "${PGDATABASE_DEV}"
    echo "cluster ready; database ${PGDATABASE_DEV} created"
    echo
    echo "put this in your .env:"
    echo "DATABASE_URL=postgres://${PGUSER_DEV}:${PGPASSWORD_DEV}@127.0.0.1:${PGPORT}/${PGDATABASE_DEV}?sslmode=disable"
}

cmd_start() {
    require_binaries
    [ -f "${PGDATA_DIR}/PG_VERSION" ] || die "no cluster at ${PGDATA_DIR}; run 'init' first"

    if cmd_status >/dev/null 2>&1; then
        echo "already running on port ${PGPORT}"
        return 0
    fi

    # pg_ctl hands its stdout to the server it spawns, so a caller that reads the
    # pipe would block for as long as the server lives. Redirect both.
    pg pg_ctl -D "${PGDATA_DIR}" -l "${LOG_FILE}" -W start >/dev/null 2>&1

    for _ in $(seq 1 30); do
        if cmd_status >/dev/null 2>&1; then
            echo "postgres listening on 127.0.0.1:${PGPORT} (log: ${LOG_FILE})"
            return 0
        fi
        sleep 1
    done

    echo "postgres did not come up; last lines of ${LOG_FILE}:" >&2
    tail -20 "${LOG_FILE}" >&2 || true
    exit 1
}

cmd_stop() {
    require_binaries
    pg pg_ctl -D "${PGDATA_DIR}" -m fast -W stop >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
        cmd_status >/dev/null 2>&1 || {
            echo "postgres stopped"
            return 0
        }
        sleep 1
    done
    die "postgres is still accepting connections"
}

cmd_status() {
    require_binaries
    pg pg_isready -h 127.0.0.1 -p "${PGPORT}" -U "${PGUSER_DEV}"
}

cmd_reset() {
    require_binaries
    cmd_start
    PGPASSWORD="${PGPASSWORD_DEV}" pg dropdb -h 127.0.0.1 -p "${PGPORT}" \
        -U "${PGUSER_DEV}" --if-exists "${PGDATABASE_DEV}"
    PGPASSWORD="${PGPASSWORD_DEV}" pg createdb -h 127.0.0.1 -p "${PGPORT}" \
        -U "${PGUSER_DEV}" "${PGDATABASE_DEV}"
    echo "database recreated; applying migrations"
    go run ./cmd/panel migrate
}

cmd_psql() {
    require_binaries
    PGPASSWORD="${PGPASSWORD_DEV}" pg psql -h 127.0.0.1 -p "${PGPORT}" \
        -U "${PGUSER_DEV}" -d "${PGDATABASE_DEV}"
}

case "${1:-}" in
    init) cmd_init ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    reset) cmd_reset ;;
    psql) cmd_psql ;;
    *)
        sed -n '3,25p' "$0" | sed 's|^# \{0,1\}||'
        exit 1
        ;;
esac
