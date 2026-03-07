#!/usr/bin/env bash
# run_all.sh — End-to-end reproduction script for the qemu-pdf-emulation experiment.
#
# Runs all steps in order:
#   1. setup.sh     — install deps, download DITA-OT / JDKs / userguide
#   2. run_native.sh — build PDF with native (x86_64) JDK
#   3. run_qemu.sh   — build PDF with QEMU-emulated aarch64 JDK
#   4. compare.sh    — assert PDF content equivalence
#
# Usage:
#   sudo ./run_all.sh        # sudo needed for apt-get in setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

step() { echo; echo "▶ $*"; echo "  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"; }

step "Step 1/4: Setup"
bash "$SCRIPT_DIR/setup.sh"

step "Step 2/4: Native PDF build"
bash "$SCRIPT_DIR/run_native.sh"

step "Step 3/4: QEMU PDF build"
bash "$SCRIPT_DIR/run_qemu.sh"

step "Step 4/4: PDF comparison"
bash "$SCRIPT_DIR/compare.sh"

echo
echo "════════════════════════════════════════════════════════"
echo " Experiment complete. Results in: $SCRIPT_DIR/results/"
echo "════════════════════════════════════════════════════════"
ls -lh "$SCRIPT_DIR/results/"*.pdf 2>/dev/null || true
cat "$SCRIPT_DIR/results/comparison/summary.txt" 2>/dev/null || true
