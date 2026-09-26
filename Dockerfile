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

# --- CA certs (lightweight source for release stage) ---
FROM alpine:latest AS certs

# --- Release stage (pre-built binary, used by CI/CD with --target release) ---
FROM scratch AS release
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chmod=755 mcp /usr/local/bin/mcp
# Scratch has no /etc/passwd, so docker defaults HOME to "/" and the config
# would resolve to /.config/mcp. Pin it so the documented
# -v ~/.config/mcp:/root/.config/mcp mount is the path the binary reads.
ENV HOME=/root
# Scratch has no writable filesystem — disable audit by default.
# Override with -e MCP_AUDIT_ENABLED=true when a volume is mounted.
ENV MCP_AUDIT_ENABLED=false
EXPOSE 8080
ENTRYPOINT ["mcp"]

# --- Runtimes shared by the `full` stages ---
#
# The scratch image runs HTTP backends only: a backend with a `command` needs
# that command on PATH, and scratch has nothing. This layer carries the
# runtimes the registry actually hands out (npx for npm packages, uvx for
# python ones, docker for OCI ones) plus the two CLI-as-MCP tools people wrap
# most often. Everything else still has to come from a derived image.
FROM alpine:latest AS runtimes
RUN apk add --no-cache \
    ca-certificates \
    nodejs npm \
    uv \
    docker-cli \
    kubectl \
    github-cli

# --- Full stage (pre-built binary, used by CI/CD with --target full) ---
FROM runtimes AS full
COPY --chmod=755 mcp /usr/local/bin/mcp
ENV HOME=/root
# This filesystem is writable, unlike scratch, but audit stays off for a
# different reason: opening the database downloads a native ChronDB library
# at startup, so an ephemeral container pays a network round trip on every
# run (and has no release to fetch on linux-aarch64). Turn it on with
# -e MCP_AUDIT_ENABLED=true and a mounted volume, or stream to the log
# driver with -e MCP_AUDIT_OUTPUT=stdout.
ENV MCP_AUDIT_ENABLED=false
EXPOSE 8080
ENTRYPOINT ["mcp"]

# --- Full stage built from source (docker build --target full-source) ---
FROM runtimes AS full-source
COPY --from=builder /app/target/release/mcp /usr/local/bin/mcp
ENV HOME=/root
ENV MCP_AUDIT_ENABLED=false
EXPOSE 8080
ENTRYPOINT ["mcp"]

# --- Default stage (build from source) ---
# Keep this last: `docker build .` with no --target builds the final stage.
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/release/mcp /usr/local/bin/mcp
# See the release stage: pin HOME so /root/.config/mcp is the config path.
ENV HOME=/root
# Scratch has no writable filesystem — disable audit by default.
# Override with -e MCP_AUDIT_ENABLED=true when a volume is mounted.
ENV MCP_AUDIT_ENABLED=false
EXPOSE 8080
ENTRYPOINT ["mcp"]
