# Multi-stage Dockerfile for agentd
#
# Builds a minimal container with the agentd binary and required
# runtime dependencies for Linux isolation features.
#
# Usage:
#   docker build -t agentd .
#   docker run --privileged agentd

# Build stage
FROM rust:bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
COPY build.rs ./build.rs
COPY proto ./proto

# Build release binary
RUN cargo build --release --bin agentd

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
# - util-linux: for unshare command (container isolation)
# - curl: for health checks
# - ca-certificates: for HTTPS
RUN apt-get update && apt-get install -y \
    util-linux \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create agentd user and directories
RUN useradd -r -s /bin/false agentd \
    && mkdir -p /var/lib/agentd/work \
    && mkdir -p /var/lib/agentd/data \
    && mkdir -p /etc/agentd/bundles \
    && mkdir -p /etc/agentd/config \
    && chown -R agentd:agentd /var/lib/agentd

# Copy binary from builder
COPY --from=builder /build/target/release/agentd /usr/local/bin/agentd

# Copy policy files
COPY policy /etc/agentd/policy

# Expose ports
# 9500: gRPC
# 8090: HTTP
EXPOSE 9500 8090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

# Note: agentd typically needs to run as root for isolation features
# (Landlock, namespaces, cgroups). In production, use more granular
# capabilities instead of running as full root.
USER root

WORKDIR /var/lib/agentd

ENTRYPOINT ["/usr/local/bin/agentd"]
CMD ["run"]
