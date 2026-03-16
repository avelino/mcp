FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY mcp /usr/local/bin/mcp
ENTRYPOINT ["mcp"]
