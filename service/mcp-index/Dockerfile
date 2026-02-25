FROM rust:1.88-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build

# Copy workspace manifests for dependency resolution
COPY Cargo.toml Cargo.lock ./

# Create stub workspace members (cargo needs them for resolution)
COPY service/mcp-sidecar/Cargo.toml service/mcp-sidecar/Cargo.toml
RUN mkdir -p service/mcp-sidecar/src && echo "fn main(){}" > service/mcp-sidecar/src/main.rs

COPY service/smith-chat/Cargo.toml service/smith-chat/Cargo.toml
RUN mkdir -p service/smith-chat/src && echo "" > service/smith-chat/src/lib.rs

COPY service/admission/Cargo.toml service/admission/Cargo.toml
RUN mkdir -p service/admission/src && echo "" > service/admission/src/lib.rs

# Copy full mcp-index source
COPY service/mcp-index/ service/mcp-index/

RUN cargo build --release --package mcp-index --bin mcp-index

FROM alpine:3.19
RUN apk add --no-cache wget
COPY --from=builder /build/target/release/mcp-index /usr/local/bin/mcp-index
ENTRYPOINT ["mcp-index"]
