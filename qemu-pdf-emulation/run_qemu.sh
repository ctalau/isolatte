#!/usr/bin/env bash
# run_qemu.sh — Build the Oxygen XML userguide (chapter subset) using QEMU system
#               emulation with full software CPU emulation (TCG, no KVM).
#
# Architecture:
#   qemu-system-x86_64 -machine accel=tcg
#     ├── Alpine Linux 3.19 "virt" kernel + initramfs (booted from ISO)
#     ├── virtio-9p shared filesystem:
#     │     /share/dita-ot/   ← DITA-OT 4.4 (host → VM, read-only-ish)
#     │     /share/userguide/ ← Oxygen userguide DITA sources (host → VM)
#     │     /share/output/    ← PDF output dir (VM → host, read-write)
#     ├── virtio-net user (SLIRP NAT) for APK package download
#     └── isa-serial over Unix socket for automated command injection
#
#   Inside the VM:
#     1. Boot Alpine in live mode (~80s under TCG)
#     2. Configure APK proxy → install openjdk21-jre-headless (~5 min)
#     3. Mount 9p share at /share
#     4. Run DITA-OT PDF build via emulated x86_64 JDK
#     5. Power off — PDF is already visible on the host via the shared dir
#
# Input: DITA/maps/chapter-getting-started.ditamap (same chapter as native run)
# Output:
#   results/qemu_chapter.pdf           — generated PDF
#   results/qemu_chapter_timing.txt    — wall-clock timing
#   results/qemu_build.log             — serial console log (full VM output)
#
# Usage:
#   ./run_qemu.sh
#   (Takes 15–40 minutes due to TCG overhead; set QEMU_TIMEOUT_MINUTES=60 to extend)
#
# Prerequisites: run setup.sh first.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="$BASE_DIR/deps"
RESULTS_DIR="$BASE_DIR/results"

DITA_OT_VERSION="4.4"
ALPINE_KERNEL="$DEPS_DIR/vmlinuz-virt"
ALPINE_INITRD="$DEPS_DIR/initramfs-virt"
ALPINE_ISO="$DEPS_DIR/alpine-virt-3.19.1-x86_64.iso"
VM_SHARE_DIR="$DEPS_DIR/vm-share"
OUTPUT_DIR="$VM_SHARE_DIR/output"
SOCK="$DEPS_DIR/qemu-serial.sock"
LOG_FILE="$RESULTS_DIR/qemu_build.log"
TIMING_FILE="$RESULTS_DIR/qemu_chapter_timing.txt"
PDF_DEST="$RESULTS_DIR/qemu_chapter.pdf"

# Host proxy settings for APK inside VM
# In QEMU user networking, all host IPs are reachable from the VM
HOST_PROXY_URL="${http_proxy:-http://21.0.0.165:15004}"

# Timeout for the full VM run (in seconds)
TIMEOUT_SECS=$(( ${QEMU_TIMEOUT_MINUTES:-45} * 60 ))

info() { echo "[qemu] $*" | tee -a "$LOG_FILE"; }
die()  { echo "[qemu] ERROR: $*" >&2; exit 1; }

mkdir -p "$RESULTS_DIR" "$OUTPUT_DIR"
rm -f "$SOCK" "$LOG_FILE"

# ── pre-flight ─────────────────────────────────────────────────────────────────
[[ -f "$ALPINE_KERNEL" ]] || die "vmlinuz-virt not found — run setup.sh first"
[[ -f "$ALPINE_INITRD" ]] || die "initramfs-virt not found — run setup.sh first"
[[ -f "$ALPINE_ISO"    ]] || die "Alpine ISO not found — run setup.sh first"
[[ -d "$VM_SHARE_DIR/dita-ot/bin" ]] || die "DITA-OT not in VM share — run setup.sh first"
[[ -d "$VM_SHARE_DIR/userguide/DITA" ]] || die "Userguide not in VM share — run setup.sh first"
command -v qemu-system-x86_64 >/dev/null 2>&1 || die "qemu-system-x86_64 not installed"
command -v socat >/dev/null 2>&1 || die "socat not installed"

info "QEMU system: $(qemu-system-x86_64 --version | head -1)"
info "Emulation  : x86_64 TCG (software, no KVM)"
info "Alpine ISO : $ALPINE_ISO"
info "Host proxy : $HOST_PROXY_URL"
info "Timeout    : ${TIMEOUT_SECS}s"

# ── write QEMU launch script ──────────────────────────────────────────────────
# Avoids shell quoting issues by putting the command in a script file.
QEMU_SCRIPT="$DEPS_DIR/qemu-launch.sh"
cat > "$QEMU_SCRIPT" <<QEOF
#!/bin/bash
exec qemu-system-x86_64 \\
  -machine accel=tcg \\
  -m 2G \\
  -smp 2 \\
  -display none \\
  -kernel "${ALPINE_KERNEL}" \\
  -initrd "${ALPINE_INITRD}" \\
  -cdrom "${ALPINE_ISO}" \\
  -append "console=ttyS0 quiet modules=loop,squashfs,sd-mod,usb-storage,9p,9pnet_virtio alpine_dev=cdrom:iso9660" \\
  -chardev "socket,id=con0,path=${SOCK},server=on,wait=off" \\
  -device "isa-serial,chardev=con0" \\
  -fsdev "local,security_model=passthrough,id=share0,path=${VM_SHARE_DIR}" \\
  -device "virtio-9p-pci,id=fs0,fsdev=share0,mount_tag=hostshare" \\
  -net nic,model=virtio \\
  -net user \\
  2>>"${LOG_FILE}"
QEOF
chmod +x "$QEMU_SCRIPT"

# ── start QEMU VM ─────────────────────────────────────────────────────────────
info "Starting QEMU VM..."
START_EPOCH=$(date +%s)

"$QEMU_SCRIPT" &
QEMU_PID=$!
info "QEMU PID: $QEMU_PID"

# Wait for socket to appear (QEMU may take a moment to set up)
for i in $(seq 1 15); do
  sleep 1
  test -S "$SOCK" && break
done
test -S "$SOCK" || die "QEMU socket not created after 15s — QEMU may have crashed"

# ── automation: inject commands via socat ─────────────────────────────────────
info "Starting serial console automation..."

# The DITA-OT build command to run inside the VM
DITA_CMD="/share/dita-ot/bin/dita"
DITA_INPUT="/share/userguide/DITA/maps/chapter-getting-started.ditamap"
DITA_OUTPUT="/share/output"

# Commands sent to the VM in sequence (timing-based automation):
#   t=0:    QEMU boots Alpine in TCG (takes ~80-100s)
#   t=90s:  Login as root
#   t=93s:  Set up proxy, configure APK, install JDK (~5-15 min under TCG)
#   t=?:    DITA_BUILD_START marker printed, DITA-OT runs (~15-60 min under TCG)
#   t=?:    DITA_BUILD_DONE marker printed
#   t=?:    poweroff

(
  # Wait for Alpine boot completion (~90s under TCG)
  sleep 95
  info "  → Sending login credentials"
  printf 'root\n'
  sleep 3

  info "  → Configuring APK proxy and installing OpenJDK"
  printf 'export http_proxy="%s" https_proxy="%s"\n' "$HOST_PROXY_URL" "$HOST_PROXY_URL"
  sleep 1
  # Configure APK proxy
  printf 'echo "http_proxy=%s" > /etc/apk/repositories.d/proxy.conf 2>/dev/null || true\n' "$HOST_PROXY_URL"
  sleep 1
  # Set APK proxy via environment and install JDK
  printf 'http_proxy="%s" https_proxy="%s" apk add --no-cache openjdk21-jre-headless 2>&1 && echo "JDK_INSTALLED_OK" || echo "JDK_INSTALL_FAILED"\n' "$HOST_PROXY_URL" "$HOST_PROXY_URL"
  # JDK install takes several minutes under TCG (APK download + extraction)
  sleep 900

  info "  → Mounting 9p share and running DITA-OT"
  printf 'mkdir -p /share && mount -t 9p -o trans=virtio,version=9p2000.L hostshare /share && echo "9P_MOUNT_OK" || echo "9P_MOUNT_FAIL"\n'
  sleep 10

  printf 'echo "DITA_BUILD_START"\n'
  sleep 1
  printf 'JAVA_HOME=/usr/lib/jvm/java-21-openjdk %s --input="%s" --format=pdf --output="%s" && echo "DITA_BUILD_OK" || echo "DITA_BUILD_FAIL"\n' "$DITA_CMD" "$DITA_INPUT" "$DITA_OUTPUT"
  # DITA-OT build takes several minutes; allow plenty of time under TCG
  sleep 3600

  printf 'echo "DITA_BUILD_DONE"\n'
  sleep 5
  printf 'ls -la %s/*.pdf 2>/dev/null && echo "PDF_LISTED" || echo "NO_PDF_FOUND"\n' "$DITA_OUTPUT"
  sleep 5
  printf 'sync\npoweroff\n'
  sleep 60

) | socat - UNIX-CONNECT:"$SOCK" >> "$LOG_FILE" 2>&1 &
SOCAT_PID=$!

# ── wait for QEMU to finish or timeout ────────────────────────────────────────
info "Waiting for QEMU VM to complete (timeout: ${TIMEOUT_SECS}s)..."

elapsed=0
while kill -0 $QEMU_PID 2>/dev/null; do
  sleep 10
  elapsed=$((elapsed + 10))

  # Check for build completion markers in log
  if grep -q "DITA_BUILD_DONE" "$LOG_FILE" 2>/dev/null; then
    info "DITA_BUILD_DONE marker found at ${elapsed}s"
    break
  fi
  if grep -q "DITA_BUILD_FAIL" "$LOG_FILE" 2>/dev/null; then
    info "WARNING: DITA_BUILD_FAIL marker found at ${elapsed}s"
    break
  fi

  if (( elapsed >= TIMEOUT_SECS )); then
    info "Timeout reached (${TIMEOUT_SECS}s)"
    break
  fi

  # Progress indicator every 60s
  if (( elapsed % 60 == 0 )); then
    info "  Still running... ${elapsed}s elapsed"
    grep -E "JDK_INSTALLED|9P_MOUNT|DITA_BUILD" "$LOG_FILE" 2>/dev/null | tail -3 || true
  fi
done

END_EPOCH=$(date +%s)
WALL_MS=$(( (END_EPOCH - START_EPOCH) * 1000 ))

# Graceful shutdown
kill $SOCAT_PID 2>/dev/null || true
if kill -0 $QEMU_PID 2>/dev/null; then
  info "Sending poweroff signal to VM..."
  echo 'poweroff' | socat - UNIX-CONNECT:"$SOCK" 2>/dev/null || true
  sleep 10
  kill $QEMU_PID 2>/dev/null || true
fi
wait $SOCAT_PID $QEMU_PID 2>/dev/null || true

# ── collect output ─────────────────────────────────────────────────────────────
info "QEMU VM exited. Checking for output..."

# The PDF should be in the shared output directory (visible on host)
PDF_FOUND=$(find "$OUTPUT_DIR" -name "*.pdf" 2>/dev/null | head -1)

if [[ -z "$PDF_FOUND" ]]; then
  info "No PDF found in $OUTPUT_DIR"
  info "Build log summary:"
  grep -E "JDK_INSTALLED|9P_MOUNT|DITA_BUILD|ERROR|FATAL" "$LOG_FILE" 2>/dev/null | tail -20 || true
  die "QEMU build did not produce a PDF. Check $LOG_FILE"
fi

cp "$PDF_FOUND" "$PDF_DEST"
PDF_SIZE=$(stat -c%s "$PDF_DEST")
PDF_SHA256=$(sha256sum "$PDF_DEST" | awk '{print $1}')

info "=== QEMU build complete ==="
info "PDF path   : $PDF_DEST"
info "PDF size   : $PDF_SIZE bytes"
info "SHA-256    : $PDF_SHA256"
info "Wall time  : ${WALL_MS}ms (including VM boot + APK install)"

cat > "$TIMING_FILE" <<EOF
=== qemu_chapter summary ===
pdf_path=$PDF_DEST
pdf_size_bytes=$PDF_SIZE
pdf_sha256=$PDF_SHA256
wall_ms=$WALL_MS
qemu_binary=$(command -v qemu-system-x86_64)
qemu_version=$(qemu-system-x86_64 --version | head -1)
emulation_mode=TCG (software, no KVM)
guest_arch=x86_64
guest_os=Alpine Linux 3.19 (virt)
alpine_iso=$(basename "$ALPINE_ISO")
dita_ot_version=$DITA_OT_VERSION
ditamap=DITA/maps/chapter-getting-started.ditamap
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
