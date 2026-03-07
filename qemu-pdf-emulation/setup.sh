#!/usr/bin/env bash
# setup.sh — Download and install all dependencies for the qemu-pdf-emulation experiment.
#
# Emulation strategy:
#   qemu-system-x86_64 with -machine accel=tcg performs FULL software CPU
#   emulation (TCG = Tiny Code Generator, no KVM, no hardware acceleration).
#   Every x86_64 instruction is translated and executed in software.
#
# What this script does:
#   1. Installs system tools: qemu-system-x86_64, qemu-utils, poppler-utils, qpdf, 7zip
#   2. Downloads DITA-OT 4.4
#   3. Downloads Oxygen XML userguide DITA sources (sparse checkout)
#   4. Downloads Alpine Linux 3.19 "virt" ISO (60 MB) for the QEMU VM
#   5. Extracts the Alpine kernel (vmlinuz-virt) and initial ramdisk (initramfs-virt)
#   6. Builds a custom "wrapper" initramfs that sets up the VM environment,
#      installs OpenJDK inside the live Alpine system, and runs DITA-OT
#
# Usage:
#   sudo ./setup.sh
#
# Re-running is safe: each step is idempotent.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="$BASE_DIR/deps"
RESULTS_DIR="$BASE_DIR/results"

DITA_OT_VERSION="4.4"
DITA_OT_URL="https://github.com/dita-ot/dita-ot/releases/download/${DITA_OT_VERSION}/dita-ot-${DITA_OT_VERSION}.zip"
DITA_OT_DIR="$DEPS_DIR/dita-ot-${DITA_OT_VERSION}"

USERGUIDE_DIR="$DEPS_DIR/userguide"
USERGUIDE_REPO="https://github.com/oxygenxml/userguide.git"
USERGUIDE_REF="master"
USERGUIDE_DITAMAP="DITA/UserManual.ditamap"

# Alpine Linux 3.19 "virt" — minimal kernel for virtual machines, 60 MB ISO
ALPINE_VERSION="3.19.1"
ALPINE_ISO_URL="https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-virt-${ALPINE_VERSION}-x86_64.iso"
ALPINE_ISO="$DEPS_DIR/alpine-virt-${ALPINE_VERSION}-x86_64.iso"
ALPINE_KERNEL="$DEPS_DIR/vmlinuz-virt"
ALPINE_INITRD="$DEPS_DIR/initramfs-virt"

info()  { echo "[setup] $*"; }
die()   { echo "[setup] ERROR: $*" >&2; exit 1; }
step()  { echo; echo "══════════════════════════════════════════════════════"; echo "[setup] $*"; echo "══════════════════════════════════════════════════════"; }

mkdir -p "$DEPS_DIR" "$RESULTS_DIR"

# ── 1. System packages ─────────────────────────────────────────────────────────
step "1/5  Installing system packages"
PKGS_NEEDED=()
for pkg in qemu-system-x86 qemu-utils poppler-utils qpdf p7zip-full genisoimage cpio; do
  dpkg -s "$pkg" &>/dev/null || PKGS_NEEDED+=("$pkg")
done

if [[ ${#PKGS_NEEDED[@]} -gt 0 ]]; then
  info "Installing: ${PKGS_NEEDED[*]}"
  apt-get update -qq --fix-missing 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --fix-missing "${PKGS_NEEDED[@]}" || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q -t noble "${PKGS_NEEDED[@]}"
else
  info "All required packages already installed"
fi

command -v qemu-system-x86_64 >/dev/null 2>&1 || die "qemu-system-x86_64 not found"
command -v qemu-img            >/dev/null 2>&1 || die "qemu-img not found"
command -v pdftoppm            >/dev/null 2>&1 || die "pdftoppm not found"
command -v qpdf                >/dev/null 2>&1 || die "qpdf not found"
command -v 7z                  >/dev/null 2>&1 || die "7z not found"

# ── 2. DITA-OT ────────────────────────────────────────────────────────────────
step "2/5  DITA-OT ${DITA_OT_VERSION}"
if [[ -x "$DITA_OT_DIR/bin/dita" ]]; then
  info "Already present at $DITA_OT_DIR"
else
  ZIP="$DEPS_DIR/dita-ot-${DITA_OT_VERSION}.zip"
  if [[ ! -f "$ZIP" ]]; then
    info "Downloading $DITA_OT_URL"
    curl -L --retry 4 --retry-delay 2 -o "$ZIP" "$DITA_OT_URL"
  fi
  info "Extracting..."
  unzip -q "$ZIP" -d "$DEPS_DIR"
  [[ -x "$DITA_OT_DIR/bin/dita" ]] || die "bin/dita not found after extraction"
  info "Extracted to $DITA_OT_DIR"
fi

# ── 3. Oxygen userguide ───────────────────────────────────────────────────────
step "3/5  Oxygen XML userguide"
if [[ -f "$USERGUIDE_DIR/$USERGUIDE_DITAMAP" ]]; then
  info "Already present at $USERGUIDE_DIR"
else
  info "Sparse-cloning $USERGUIDE_REPO ..."
  rm -rf "$USERGUIDE_DIR"
  git clone \
    --filter=blob:none \
    --sparse \
    --depth=1 \
    --branch "$USERGUIDE_REF" \
    "$USERGUIDE_REPO" \
    "$USERGUIDE_DIR"
  (cd "$USERGUIDE_DIR" && git sparse-checkout set DITA/)
  [[ -f "$USERGUIDE_DIR/$USERGUIDE_DITAMAP" ]] || \
    die "UserManual.ditamap not found after sparse checkout"
  info "Cloned to $USERGUIDE_DIR"
fi
(cd "$USERGUIDE_DIR" && git rev-parse HEAD) > "$RESULTS_DIR/userguide_commit.txt"
info "Commit: $(cat "$RESULTS_DIR/userguide_commit.txt")"

# ── 4. Alpine Linux ISO + kernel extraction ───────────────────────────────────
step "4/5  Alpine Linux ${ALPINE_VERSION} virt ISO"
if [[ ! -f "$ALPINE_ISO" ]]; then
  info "Downloading Alpine Linux virt ISO (60 MB)..."
  curl -L --retry 4 --retry-delay 2 -o "$ALPINE_ISO" "$ALPINE_ISO_URL"
  info "Downloaded: $ALPINE_ISO"
else
  info "Already present: $ALPINE_ISO"
fi

if [[ ! -f "$ALPINE_KERNEL" || ! -f "$ALPINE_INITRD" ]]; then
  info "Extracting kernel and initramfs from ISO..."
  # Alpine virt ISO has boot/vmlinuz-virt and boot/initramfs-virt
  7z e -y "$ALPINE_ISO" "boot/vmlinuz-virt"  -o"$DEPS_DIR" >/dev/null
  7z e -y "$ALPINE_ISO" "boot/initramfs-virt" -o"$DEPS_DIR" >/dev/null
  [[ -f "$ALPINE_KERNEL" ]] || die "vmlinuz-virt not found in ISO"
  [[ -f "$ALPINE_INITRD" ]] || die "initramfs-virt not found in ISO"
  info "Kernel : $ALPINE_KERNEL ($(stat -c%s "$ALPINE_KERNEL") bytes)"
  info "Initrd : $ALPINE_INITRD ($(stat -c%s "$ALPINE_INITRD") bytes)"
else
  info "Kernel and initramfs already extracted"
fi

# ── 5. VM share directory (9p) ────────────────────────────────────────────────
step "5/5  Setting up VM shared directories"
VM_SHARE_DIR="$DEPS_DIR/vm-share"
mkdir -p "$VM_SHARE_DIR/dita-ot"
mkdir -p "$VM_SHARE_DIR/userguide"
mkdir -p "$VM_SHARE_DIR/output"

# Symlink DITA-OT and userguide into the share directory for 9p access
if [[ ! -e "$VM_SHARE_DIR/dita-ot/bin" ]]; then
  info "Linking DITA-OT into VM share..."
  # Use actual copy so 9p doesn't need to traverse symlinks
  cp -rp "$DITA_OT_DIR/." "$VM_SHARE_DIR/dita-ot/"
fi

if [[ ! -e "$VM_SHARE_DIR/userguide/DITA" ]]; then
  info "Linking userguide into VM share..."
  cp -rp "$USERGUIDE_DIR/." "$VM_SHARE_DIR/userguide/"
fi

# ── summary ───────────────────────────────────────────────────────────────────
step "Setup complete"
cat <<SUMMARY
  DITA-OT          : $DITA_OT_DIR
  Oxygen userguide : $USERGUIDE_DIR
  Alpine ISO       : $ALPINE_ISO
  Alpine kernel    : $ALPINE_KERNEL
  Alpine initrd    : $ALPINE_INITRD
  VM share dir     : $VM_SHARE_DIR
  Results dir      : $RESULTS_DIR
SUMMARY
