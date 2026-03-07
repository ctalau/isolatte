#!/usr/bin/env bash
# Run node v10 using podman and print the version.
#
# This environment runs on kernel 4.4.0 with a 9p root filesystem.
# The constraints require:
#   - storage driver: vfs (overlay and fuse-overlayfs don't work on 9p/kernel 4.4)
#   - network mode: host (netavark and CNI bridge both fail on kernel 4.4)
#
# Setup (run once as root):
#   apt-get install -y podman
#   cat > /etc/containers/storage.conf <<'EOF'
#   [storage]
#   driver = "vfs"
#   runroot = "/run/containers/storage"
#   graphroot = "/var/lib/containers/storage"
#   EOF
#   cat > /etc/containers/containers.conf <<'EOF'
#   [network]
#   network_backend = "cni"
#   EOF

set -euo pipefail

podman run --rm --network=host node:10 node --version
