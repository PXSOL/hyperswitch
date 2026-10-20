# Migration Runner Dockerfile for Hyperswitch
# This image contains migration files and diesel CLI for offline migration execution

FROM debian:trixie-slim

# Install necessary packages
RUN apt-get update && apt-get install -y \
    curl \
    tar \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Create the 'app' user and group
RUN useradd --user-group --system --create-home --no-log-init app

# Switch to the 'app' user
USER app:app

# Install diesel CLI (pinned: the version the production upgrade was rehearsed with)
RUN curl --proto '=https' --tlsv1.2 -LsSf https://github.com/diesel-rs/diesel/releases/download/v2.3.14/diesel_cli-installer.sh | sh

ENV PATH="/home/app/.cargo/bin:$PATH"

# Set working directory
WORKDIR /hyperswitch

# Copy migration files and diesel config from the workspace
COPY --chown=app:app ./migrations/ ./migrations/
# Migration-only config (no [print_schema]); see docker/migration-runner.diesel.toml.
COPY --chown=app:app ./docker/migration-runner.diesel.toml ./diesel.toml

# Copy the migration runner script
COPY --chown=app:app ./scripts/migration_runner_entrypoint.sh ./migration_runner_entrypoint.sh

# Default command to run migrations
CMD ["./migration_runner_entrypoint.sh"]
