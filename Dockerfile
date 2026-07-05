# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1.96-bookworm AS build
WORKDIR /src

# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
COPY crates/kvp-core/Cargo.toml crates/kvp-core/Cargo.toml
COPY crates/kvp-cli/Cargo.toml crates/kvp-cli/Cargo.toml
COPY crates/kvp-web/Cargo.toml crates/kvp-web/Cargo.toml

# Build the full workspace.
COPY . .
RUN cargo build --release --bin kvp-web

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime
# native-tls links against the system OpenSSL; ca-certificates for TLS trust;
# curl for the container HEALTHCHECK.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home appuser

COPY --from=build /src/target/release/kvp-web /usr/local/bin/kvp-web

USER appuser
ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/kvp-web"]
