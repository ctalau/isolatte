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

# `runsc do --network=host` shells out to `ip route list default` to find the
# host interface to bridge into the sandbox's veth/NAT setup. If `ip` is
# missing, it silently falls back to an isolated network namespace (logging
# only "Network interface not found, using internal network" to its debug
# log) and every fetch then fails with EAI_AGAIN — easy to mistake for the
# unrelated startup race documented in the README.
if ! command -v ip &>/dev/null; then
  echo "Error: 'ip' (iproute2) is not installed. runsc needs it to set up" >&2
  echo "       host networking — without it the sandbox silently gets no" >&2
  echo "       network access. Install it with: apt-get install -y iproute2" >&2
  exit 1
fi

exec runsc -ignore-cgroups --network=host do \
  node --use-env-proxy "$SCRIPT_DIR/fetch-oxygen.mjs"
