# SAACP-rs multi-stage Dockerfile
# Build stage: compiles the daemon binaries
# Runtime stage: distroless image with just the binaries

# ── Build stage ────────────────────────────────────────────────────────────
# Toolchain pin MUST match the crate's real MSRV floor: the code uses
# language features stable only in 1.80+ (see the rust-version note in
# Cargo.toml); rust:1.79 predates them and fails to compile. 1.96 matches
# rust-toolchain.toml.
FROM rust:1.96-slim-bookworm AS builder

# Install build dependencies. No libssl-dev: every TLS path in this crate is
# rustls-based and `cargo tree -i openssl -e normal` for the release bins
# resolves to nothing — OpenSSL only enters the lockfile via dev-dependencies,
# which `cargo build --bins` never compiles.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/saacp

# G3/M7: Cargo workspace — must copy workspace member manifests alongside root.
# The build layer cache is: workspace Cargo.toml + member manifests → cargo fetch
# → src + crates/*/src → cargo build. Separating manifest copy from source copy
# lets Docker re-use the dep-download layer when only src/ changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/saacp-primitives/Cargo.toml crates/saacp-primitives/Cargo.toml
COPY crates/saacp-crypto/Cargo.toml crates/saacp-crypto/Cargo.toml
COPY src/ src/
COPY crates/ crates/

# Build release binaries with production features
# M-C remediation (production audit G3/R3): `health-endpoint` is compiled in
# so the daemon health/metrics server (/healthz /readyz /metrics) is available
# to container orchestrators, not just the sidecar's own HTTP API.
# M5 remediation: `webhook-alerts` for HTTP webhook alert delivery.
# M2 remediation: `redis-backend` for shared state across nodes.
RUN cargo build --release --bins --features "transport-ws transport-tls sidecar command-center health-endpoint webhook-alerts redis-backend"

# ── Runtime stage ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy binaries from builder
COPY --from=builder /usr/src/saacp/target/release/saacp-sidecar /usr/local/bin/
COPY --from=builder /usr/src/saacp/target/release/saacp-command-center /usr/local/bin/

# Default to the sidecar binary (most common deployment)
ENTRYPOINT ["/usr/local/bin/saacp-sidecar"]
