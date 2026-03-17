#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# QEMU software-emulation wrapper
#
# Runs the Docker sandbox tests inside a QEMU virtual machine so
# that even a compromised container cannot escape to the real host.
#
# Requirements on the host:
#   - qemu-system-x86_64 (or qemu-system-aarch64 on ARM hosts)
#   - A cloud-init-capable Linux image (we download one if absent)
#   - cloud-localds (from cloud-image-utils / cloud-utils)
#
# The VM:
#   - Boots with software emulation (no KVM) as requested
#   - Gets a user-mode (SLIRP) network with outbound NAT
#   - Has Docker pre-installed via cloud-init
#   - Mounts this project directory via a 9p virtio share
#   - Runs run_tests.sh and streams output to the terminal
#
# Usage:
#   ./run_qemu_tests.sh
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")"

WORK_DIR="$(pwd)/.qemu-work"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
BASE_IMAGE="$WORK_DIR/noble-base.img"
VM_DISK="$WORK_DIR/vm-disk.qcow2"
SEED_ISO="$WORK_DIR/seed.iso"
VM_MEM="4G"
VM_CPUS="2"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { printf "${CYAN}▸ %s${NC}\n" "$*"; }
ok()   { printf "${GREEN}✓ %s${NC}\n" "$*"; }
fail() { printf "${RED}✗ %s${NC}\n" "$*"; }

mkdir -p "$WORK_DIR"

# ── 1. Obtain base cloud image ────────────────────────────────────
if [ ! -f "$BASE_IMAGE" ]; then
  info "Downloading Ubuntu Noble cloud image …"
  curl -L -o "$BASE_IMAGE" "$IMAGE_URL"
fi

# Create a copy-on-write overlay so the base stays clean
info "Creating VM disk overlay …"
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$VM_DISK" 20G

# ── 2. Build cloud-init data ──────────────────────────────────────
info "Generating cloud-init seed …"

cat > "$WORK_DIR/user-data" <<'USERDATA'
#cloud-config
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash

package_update: true
packages:
  - docker.io
  - docker-compose-v2

runcmd:
  - systemctl enable --now docker
  - usermod -aG docker tester
  # Run the sandbox tests and write exit code to a sentinel file
  - |
    su - tester -c '
      set -ex
      cd /mnt/project
      bash run_tests.sh 2>&1 | tee /tmp/test-output.log
      echo $? > /tmp/test-exit-code
    '
  # Signal completion — the host watches for this via serial
  - echo "@@TESTS_DONE@@:$(cat /tmp/test-exit-code)" > /dev/ttyS0
  - shutdown -h now

USERDATA

cat > "$WORK_DIR/meta-data" <<META
instance-id: sandbox-test-vm
local-hostname: sandbox-test-vm
META

# Build the seed ISO (cloud-localds or genisoimage)
if command -v cloud-localds &>/dev/null; then
  cloud-localds "$SEED_ISO" "$WORK_DIR/user-data" "$WORK_DIR/meta-data"
elif command -v genisoimage &>/dev/null; then
  genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock \
    "$WORK_DIR/user-data" "$WORK_DIR/meta-data"
else
  fail "Need cloud-localds or genisoimage to build seed ISO"
  echo "  Install: apt-get install cloud-image-utils  OR  genisoimage"
  exit 1
fi

# ── 3. Launch QEMU (software emulation, no KVM) ──────────────────
info "Launching QEMU VM (software emulation) …"
info "  CPU=${VM_CPUS}  MEM=${VM_MEM}  DISK=20G"
info "  The project directory is shared as a 9p mount at /mnt/project"
echo ""

RESULT_FILE="$WORK_DIR/serial.log"
: > "$RESULT_FILE"

timeout 1800 qemu-system-x86_64 \
  -machine q35 \
  -cpu qemu64 \
  -smp "$VM_CPUS" \
  -m "$VM_MEM" \
  -nographic \
  -serial mon:stdio \
  -drive file="$VM_DISK",format=qcow2,if=virtio \
  -drive file="$SEED_ISO",format=raw,if=virtio \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0 \
  -virtfs local,path="$(pwd)",mount_tag=project,security_model=mapped-xattr,id=project0 \
  -append "root=/dev/vda1 console=ttyS0" \
  2>&1 | tee "$RESULT_FILE" || true

# ── 4. Extract result ─────────────────────────────────────────────
echo ""
if grep -q "@@TESTS_DONE@@" "$RESULT_FILE"; then
  EXIT_CODE=$(grep "@@TESTS_DONE@@" "$RESULT_FILE" | tail -1 | sed 's/.*@@TESTS_DONE@@://' | tr -cd '0-9')
  if [ "${EXIT_CODE:-1}" = "0" ]; then
    ok "All tests passed inside QEMU VM"
  else
    fail "Tests failed inside QEMU VM (exit code: $EXIT_CODE)"
  fi
  exit "${EXIT_CODE:-1}"
else
  fail "VM did not complete tests (timeout or crash)"
  exit 1
fi
