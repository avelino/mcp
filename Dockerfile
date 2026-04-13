# --- Build stage (Alpine = native musl, no cross-compile wrapper) ---
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app

# Cache dependencies: copy manifests first, build a dummy project
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Build the real binary
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# --- Runtime stage (scratch = only binary + CA certs) ---
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/release/mcp /usr/local/bin/mcp

EXPOSE 8080
ENTRYPOINT ["mcp"]
