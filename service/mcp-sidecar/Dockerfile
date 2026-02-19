FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build

# Copy workspace manifests for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Create stub workspace members (cargo needs them for resolution)
COPY service/mcp-index/Cargo.toml service/mcp-index/Cargo.toml
RUN mkdir -p service/mcp-index/src && echo "fn main(){}" > service/mcp-index/src/main.rs

COPY service/smith-chat/Cargo.toml service/smith-chat/Cargo.toml
RUN mkdir -p service/smith-chat/src && echo "" > service/smith-chat/src/lib.rs

COPY service/admission/Cargo.toml service/admission/Cargo.toml
RUN mkdir -p service/admission/src && echo "" > service/admission/src/lib.rs

# Copy full mcp-sidecar source
COPY service/mcp-sidecar/ service/mcp-sidecar/

RUN cargo build --release --package mcp-sidecar --bin mcp-sidecar

FROM alpine:3.19
RUN apk add --no-cache wget
COPY --from=builder /build/target/release/mcp-sidecar /usr/local/bin/mcp-sidecar
ENTRYPOINT ["mcp-sidecar"]
