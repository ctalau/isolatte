FROM node:22-bookworm-slim

# Install bubblewrap (bwrap) and git (needed by Claude Code)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap \
    git \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install Claude Code globally
RUN npm install -g @anthropic-ai/claude-code

# The workspace directory is mounted at runtime
RUN mkdir -p /workspace

WORKDIR /workspace

# Run as root so bwrap can mount /proc for the sandbox.
# The container already provides isolation via Docker; bwrap adds a second
# layer of subprocess env-scrubbing inside that.
ENTRYPOINT ["claude"]
CMD ["--help"]
