#!/usr/bin/env bash
# Runs fetch-oxygen.mjs inside a gVisor sandbox (`runsc do`) with host
# networking. Any HTTP_PROXY / HTTPS_PROXY / NO_PROXY already set in the
# calling shell are forwarded automatically — `runsc do` passes the parent
# environment through to the sandboxed process unchanged.
#
# Usage:
#   ./run.sh
#   HTTPS_PROXY=http://192.168.10.3:3128 ./run.sh   # route through a proxy
#
# Requires runsc (gVisor) and root (or CAP_SYS_ADMIN) — see README.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v runsc &>/dev/null; then
  echo "Error: runsc (gVisor) is not installed. See README.md for setup." >&2
  exit 1
fi

exec runsc -ignore-cgroups --network=host do \
  node --use-env-proxy "$SCRIPT_DIR/fetch-oxygen.mjs"
