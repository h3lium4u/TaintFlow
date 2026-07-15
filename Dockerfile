# Multi-stage hardened build for TaintFlow SAST Engine
# Stage 1: Build binary statically using Rust Musl target
FROM clux/muslrust:stable AS builder
WORKDIR /volume
COPY rust-engine /volume/rust-engine
RUN cargo build --release --target x86_64-unknown-linux-musl --manifest-path rust-engine/Cargo.toml

# Stage 2: Distribute with minimal static sandbox
FROM alpine:latest
LABEL org.opencontainers.image.title="TaintFlow"
LABEL org.opencontainers.image.description="Offline Context-Sensitive Static Application Security Testing (SAST) Engine written in Rust."
LABEL org.opencontainers.image.version="v1.0.0"
LABEL org.opencontainers.image.source="https://github.com/h3lium4u/TaintFlow"
RUN addgroup -S taintflow && adduser -S taintflow -G taintflow
COPY --from=builder /volume/rust-engine/target/x86_64-unknown-linux-musl/release/taintflow-cli /usr/local/bin/taintflow-cli
USER taintflow
ENTRYPOINT ["/usr/local/bin/taintflow-cli"]

