#!/usr/bin/env bash
# Run Claude Code in a Docker container with bubblewrap sandbox enabled.
#
# Usage:
#   ./run-claude.sh [claude args...]
#   ./run-claude.sh --build         # rebuild the image first
#
# Environment variables:
#   ANTHROPIC_API_KEY  (required) — your Anthropic API key
#   WORKSPACE          (optional) — host path to mount as /workspace (default: current directory)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="claude-code-sandbox"
WORKSPACE="${WORKSPACE:-$(pwd)}"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "Error: ANTHROPIC_API_KEY is not set." >&2
  echo "  export ANTHROPIC_API_KEY=sk-ant-..." >&2
  exit 1
fi

# Build the image if requested or if it doesn't exist yet
if [[ "${1:-}" == "--build" ]] || ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
  echo "Building Claude Code Docker image..."
  docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"
  [[ "${1:-}" == "--build" ]] && shift || true
fi

echo "Starting Claude Code in Docker (workspace: $WORKSPACE)..."

# Capabilities needed for bubblewrap inside Docker:
#   SYS_ADMIN  — allows mounting /proc in the bwrap sandbox
#   SETUID/SETGID — allows bwrap to set up the namespace uid/gid mapping
# seccomp/apparmor are unconfined so bwrap syscalls are not blocked.
exec docker run --rm -it \
  --name "claude-code-$$" \
  --cap-add SYS_ADMIN \
  --cap-add SETUID \
  --cap-add SETGID \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v "${WORKSPACE}:/workspace" \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  "$IMAGE_NAME" "$@"
