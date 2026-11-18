#! /usr/bin/env bash

set -eo pipefail

# Check if DATABASE_URL is provided, otherwise construct it from individual components
if [[ -z "${DATABASE_URL:-}" ]]; then
    if [[ -z "${POSTGRES_HOST:-}" || -z "${POSTGRES_USER:-}" || -z "${POSTGRES_PASSWORD:-}" || -z "${POSTGRES_DB:-}" ]]; then
        echo 'Error: Either DATABASE_URL or all of POSTGRES_HOST, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB must be provided'
        exit 1
    fi
    export DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT:-5432}/${POSTGRES_DB}"
fi

# Run diesel migrations.
# diesel prints the whole DATABASE_URL, password included, when it cannot connect,
# so the password is masked before the output reaches the container logs.
# pipefail keeps diesel's exit status.
diesel migration run 2>&1 | sed -E 's#(postgres(ql)?://[^:/@]*:)[^@]*@#\1***@#g'

# Deployed as a long-running service (a PaaS app with a restart policy), a clean exit
# makes the platform start the container again in a loop. With
# MIGRATION_RUNNER_KEEP_ALIVE=true the container stays up after a successful run and
# stops cleanly on SIGTERM. A failed run still exits non-zero, so the restart policy
# retries it. Default: exit, as one-shot runners (docker compose) expect.
if [[ "${MIGRATION_RUNNER_KEEP_ALIVE:-false}" == "true" ]]; then
    echo 'Migrations applied. MIGRATION_RUNNER_KEEP_ALIVE=true: staying up until stopped.'
    trap 'exit 0' TERM INT
    while true; do
        sleep 86400 &
        wait $!
    done
fi
