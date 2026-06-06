#!/usr/bin/env bash
# nested-docker-qemu-tcg/run.sh
#
# Boots an Alpine Linux VM in QEMU TCG (software emulation, no /dev/kvm),
# then runs:
#   privileged docker:dind (L1)
#     └── privileged docker:dind (L2)
#           └── node:alpine  →  console.log("deep hello world")
#
# Expected total runtime: 20-60 min in TCG mode.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${SCRIPT_DIR}/work"
CACHE_DIR="${SCRIPT_DIR}/cache"
LOG_FILE="${WORK_DIR}/qemu-output.log"

ALPINE_VERSION="3.20"
ALPINE_PATCH="0"
ALPINE_IMG="generic_alpine-${ALPINE_VERSION}.${ALPINE_PATCH}-x86_64-bios-cloudinit-r0.qcow2"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/cloud/${ALPINE_IMG}"

DISK_SIZE="10G"
VM_RAM_MB="4096"
VM_CPUS="2"
VM_TIMEOUT_MINUTES="90"

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[info]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }

# ── Dependency check ───────────────────────────────────────────────────────────

check_deps() {
  info "Checking dependencies..."

  local missing=()
  command -v qemu-system-x86_64 &>/dev/null || missing+=(qemu-system-x86)
  command -v qemu-img           &>/dev/null || missing+=(qemu-utils)
  command -v mkfs.fat           &>/dev/null || missing+=(dosfstools)
  command -v mcopy              &>/dev/null || missing+=(mtools)
  command -v wget               &>/dev/null || missing+=(wget)

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing packages: ${missing[*]}"
    info "Installing..."
    apt-get install -y "${missing[@]}"
  fi

  # Confirm TCG mode is available (it's always available; KVM is not required)
  info "QEMU version: $(qemu-system-x86_64 --version | head -1)"
  info "No /dev/kvm required — using TCG software emulation."
}

# ── Download Alpine cloud image ────────────────────────────────────────────────

download_image() {
  mkdir -p "$CACHE_DIR"
  local cached="${CACHE_DIR}/${ALPINE_IMG}"

  if [[ -f "$cached" ]]; then
    info "Using cached image: $cached"
    return
  fi

  info "Downloading Alpine ${ALPINE_VERSION} cloud image (~179 MB)..."
  info "URL: ${ALPINE_URL}"
  wget --progress=bar:force -O "$cached" "$ALPINE_URL" || {
    rm -f "$cached"
    error "Download failed."
    exit 1
  }
  info "Download complete."
}

# ── Create working disk image ──────────────────────────────────────────────────

prepare_disk() {
  mkdir -p "$WORK_DIR"
  local disk="${WORK_DIR}/disk.qcow2"
  local cached="${CACHE_DIR}/${ALPINE_IMG}"

  if [[ -f "$disk" ]]; then
    warn "Removing previous working disk: $disk"
    rm -f "$disk"
  fi

  info "Creating working copy of disk image..."
  cp "$cached" "$disk"

  info "Resizing disk to ${DISK_SIZE} (for Docker images and layers)..."
  qemu-img resize "$disk" "$DISK_SIZE"
  info "Disk ready: $disk"
}

# ── Create cloud-init cidata image (NoCloud data source) ──────────────────────

create_cidata() {
  local cidata="${WORK_DIR}/cidata.img"

  info "Creating cloud-init cidata image..."
  # 1 MB FAT image labelled "cidata" — cloud-init NoCloud detects this
  dd if=/dev/zero of="$cidata" bs=1M count=1 status=none
  mkfs.fat -F 12 -n "cidata" "$cidata" >/dev/null

  # Use mtools to copy files without needing root/loop devices
  MTOOLS_SKIP_CHECK=1 mcopy -i "$cidata" "${SCRIPT_DIR}/user-data" ::user-data
  MTOOLS_SKIP_CHECK=1 mcopy -i "$cidata" "${SCRIPT_DIR}/meta-data" ::meta-data

  info "cidata image ready: $cidata"
}

# ── Boot QEMU in TCG mode ──────────────────────────────────────────────────────

run_qemu() {
  local disk="${WORK_DIR}/disk.qcow2"
  local cidata="${WORK_DIR}/cidata.img"

  info "Booting VM in QEMU TCG mode..."
  info "  RAM: ${VM_RAM_MB} MB | vCPUs: ${VM_CPUS} | Accel: tcg"
  info "  Timeout: ${VM_TIMEOUT_MINUTES} minutes"
  info "  Log: $LOG_FILE"
  info ""
  warn "This will take a long time in TCG (software emulation) mode."
  warn "Estimated time: 20-60 minutes depending on Docker Hub speed."
  info ""

  # Boot QEMU with nographic (all VM console output → serial → stdout).
  # -nographic:  no display window; serial port 0 connected to stdio.
  # cloud-init console output lands in serial.log because the Alpine
  # cloud image kernel is configured with console=ttyS0.
  qemu-system-x86_64 \
    -M pc \
    -cpu max \
    -accel tcg,thread=multi \
    -m "${VM_RAM_MB}" \
    -smp "${VM_CPUS}" \
    -drive "file=${disk},format=qcow2,if=virtio,cache=writeback" \
    -drive "file=${cidata},format=raw,if=virtio,media=cdrom,read-only=on" \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    -no-reboot \
    2>&1 | tee "$LOG_FILE" &

  QEMU_PID=$!
  info "QEMU PID: $QEMU_PID"
}

# ── Monitor output for completion ──────────────────────────────────────────────

wait_for_result() {
  local deadline=$(( $(date +%s) + VM_TIMEOUT_MINUTES * 60 ))
  local last_line_count=0
  local check_interval=15

  info "Monitoring VM output (polling every ${check_interval}s)..."
  info "Watching: $LOG_FILE"

  while true; do
    # Check if QEMU has exited
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
      warn "QEMU process exited."
      break
    fi

    # Check timeout
    if [[ $(date +%s) -gt $deadline ]]; then
      error "Timeout after ${VM_TIMEOUT_MINUTES} minutes."
      kill "$QEMU_PID" 2>/dev/null || true
      return 1
    fi

    # Print new log lines (live tail)
    local current_count
    current_count=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$current_count" -gt "$last_line_count" ]]; then
      tail -n +"$((last_line_count + 1))" "$LOG_FILE" | head -n 200
      last_line_count=$current_count
    fi

    # Check for terminal markers
    if grep -q "EXPERIMENT_DONE" "$LOG_FILE" 2>/dev/null; then
      info "Found EXPERIMENT_DONE marker — success!"
      kill "$QEMU_PID" 2>/dev/null || true
      return 0
    fi

    if grep -q "EXPERIMENT_FAILED" "$LOG_FILE" 2>/dev/null; then
      error "Found EXPERIMENT_FAILED marker — experiment failed."
      kill "$QEMU_PID" 2>/dev/null || true
      return 1
    fi

    sleep "$check_interval"
  done

  # QEMU exited — check if we got a result
  if grep -q "EXPERIMENT_DONE" "$LOG_FILE" 2>/dev/null; then
    info "EXPERIMENT_DONE found in log."
    return 0
  fi

  return 1
}

# ── Report ─────────────────────────────────────────────────────────────────────

report() {
  local status="$1"
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "  EXPERIMENT REPORT"
  echo "════════════════════════════════════════════════════════════"

  if [[ "$status" == "ok" ]]; then
    echo -e "${GREEN}  Result: SUCCESS${NC}"
    local result
    result=$(grep "EXPERIMENT_DONE" "$LOG_FILE" | tail -1)
    echo "  $result"
  else
    echo -e "${RED}  Result: FAILED${NC}"
    echo ""
    echo "  Last 30 lines of VM output:"
    tail -30 "$LOG_FILE" | sed 's/^/    /'
  fi

  echo ""
  echo "  Full log: $LOG_FILE"
  echo "════════════════════════════════════════════════════════════"
}

# ── Main ───────────────────────────────────────────────────────────────────────

main() {
  echo "════════════════════════════════════════════════════════════"
  echo "  nested-docker-qemu-tcg experiment"
  echo "  QEMU TCG → docker:dind (L1) → docker:dind (L2) → node"
  echo "════════════════════════════════════════════════════════════"
  echo ""

  check_deps
  download_image
  prepare_disk
  create_cidata
  run_qemu

  if wait_for_result; then
    report ok
  else
    report fail
    exit 1
  fi
}

main "$@"
