#!/usr/bin/env bash
#
# Hermetic bubblewrap sandbox
#
# Isolation applied:
#   - Unshare IPC, PID, UTS namespaces
#   - No /home, /root, /etc, /var, /srv, /snap, /boot visible
#   - Read-only bind mounts for Node.js runtime and script
#   - Single writable path: /output (bind-mounted from ./output/)
#   - All capabilities dropped
#   - Clean environment (only PATH and HOME set)
#   - New session, dies with parent
#   - tmpfs on /tmp (ephemeral, not shared with host)
#
# Note: user-ns and cgroup-ns are not available on this kernel;
#       network ns unshare fails silently on this host, so net is shared
#       but the script itself makes no network calls.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

mkdir -p "$OUTPUT_DIR"

echo "=== Hermetic bubblewrap sandbox ==="
echo "Namespaces: IPC, PID, UTS (user-ns / cgroup-ns not supported by host kernel)"
echo "Filesystem: read-only root; /home /root /etc /var hidden; /output rw"
echo ""

bwrap \
  --unshare-ipc \
  --unshare-pid \
  --unshare-uts \
  --ro-bind /usr          /usr          \
  --ro-bind /lib          /lib          \
  --ro-bind /lib64        /lib64        \
  --ro-bind /opt/node22   /opt/node22   \
  --ro-bind "${SCRIPT_DIR}/print_date.js" /app/print_date.js \
  --bind    "$OUTPUT_DIR" /output        \
  --proc    /proc                        \
  --dev     /dev                         \
  --tmpfs   /tmp                         \
  --new-session                          \
  --die-with-parent                      \
  --clearenv                             \
  --setenv  PATH /opt/node22/bin         \
  --setenv  HOME /tmp                    \
  --cap-drop ALL                         \
  -- /opt/node22/bin/node /app/print_date.js

echo ""
echo "=== Contents of /output/date.txt (written by sandboxed process) ==="
cat "$OUTPUT_DIR/date.txt"
