#!/usr/bin/env bash
# run_native.sh — Build Oxygen XML userguide PDFs using the host (native x86_64) JDK.
#
# Two builds are performed:
#   1. Full userguide (UserManual.ditamap) — for wall-clock timing reference only
#   2. Chapter subset (chapter-getting-started.ditamap) — for content comparison
#      with the QEMU-emulated run in run_qemu.sh
#
# Output files:
#   results/native_full.pdf          — full userguide PDF
#   results/native_chapter.pdf       — getting-started chapter PDF (comparison target)
#   results/native_full_timing.txt   — GNU time stats for full build
#   results/native_chapter_timing.txt — GNU time stats for chapter build
#   results/native_build.log         — combined DITA-OT build log
#
# Usage:
#   ./run_native.sh
#
# Prerequisites: run setup.sh first.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="$BASE_DIR/deps"
RESULTS_DIR="$BASE_DIR/results"

DITA_OT_VERSION="4.4"
DITA_OT_DIR="$DEPS_DIR/dita-ot-${DITA_OT_VERSION}"
USERGUIDE_DIR="$DEPS_DIR/userguide"
FULL_MAP="$USERGUIDE_DIR/DITA/UserManual.ditamap"
CHAPTER_MAP="$USERGUIDE_DIR/DITA/maps/chapter-getting-started.ditamap"

info() { echo "[native] $*"; }
die()  { echo "[native] ERROR: $*" >&2; exit 1; }

mkdir -p "$RESULTS_DIR"

# ── pre-flight ─────────────────────────────────────────────────────────────────
[[ -x "$DITA_OT_DIR/bin/dita" ]] || die "DITA-OT not found — run setup.sh first"
[[ -f "$FULL_MAP"    ]]          || die "UserManual.ditamap not found"
[[ -f "$CHAPTER_MAP" ]]          || die "chapter-getting-started.ditamap not found"
command -v java >/dev/null 2>&1  || die "java not on PATH"

info "Native JDK  : $(java -version 2>&1 | head -1)"
info "Architecture: $(uname -m)"

# ── helper: run one DITA build and record timing ───────────────────────────────
run_build() {
  local label="$1"
  local ditamap="$2"
  local output_dir="$RESULTS_DIR/${label}_out"
  local timing_file="$RESULTS_DIR/${label}_timing.txt"
  local log_file="$RESULTS_DIR/${label}_build.log"
  local pdf_dest="$RESULTS_DIR/${label}.pdf"

  info "Building: $label"
  info "  Input : $ditamap"
  info "  Output: $output_dir"

  rm -rf "$output_dir"
  mkdir -p "$output_dir"

  local start_ns
  start_ns=$(date +%s%N)

  /usr/bin/time -v \
    bash -c "JAVA_HOME='' \"$DITA_OT_DIR/bin/dita\" \
      --input='$ditamap' \
      --format=pdf \
      --output='$output_dir' \
      --logfile='$log_file' \
      2>&1" \
    2>"$timing_file" || {
      info "DITA-OT returned non-zero; checking for PDF anyway..."
    }

  local end_ns
  end_ns=$(date +%s%N)
  local wall_ms=$(( (end_ns - start_ns) / 1000000 ))

  local pdf_found
  pdf_found=$(find "$output_dir" -name "*.pdf" 2>/dev/null | head -1)
  [[ -n "$pdf_found" ]] || { info "WARNING: No PDF found in $output_dir"; return 1; }

  cp "$pdf_found" "$pdf_dest"
  local pdf_size
  pdf_size=$(stat -c%s "$pdf_dest")
  local pdf_sha256
  pdf_sha256=$(sha256sum "$pdf_dest" | awk '{print $1}')

  info "  Done — ${wall_ms}ms, PDF: $pdf_size bytes, SHA-256: $pdf_sha256"

  cat >> "$timing_file" << EOF

=== ${label} summary ===
pdf_path=$pdf_dest
pdf_size_bytes=$pdf_size
pdf_sha256=$pdf_sha256
wall_ms=$wall_ms
java_binary=$(command -v java)
java_version=$(java -version 2>&1 | head -1)
arch=$(uname -m)
dita_ot_version=$DITA_OT_VERSION
ditamap=$ditamap
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
EOF
}

# ── build 1: chapter subset (used for comparison with QEMU) ───────────────────
info "=== Build 1/2: Getting-started chapter (comparison target) ==="
run_build "native_chapter" "$CHAPTER_MAP"

# ── build 2: full userguide (timing reference) ────────────────────────────────
info "=== Build 2/2: Full userguide (timing reference only) ==="
run_build "native_full" "$FULL_MAP"

info "=== Native runs complete ==="
info "  Chapter PDF : $(stat -c%s "$RESULTS_DIR/native_chapter.pdf" 2>/dev/null || echo N/A) bytes"
info "  Full PDF    : $(stat -c%s "$RESULTS_DIR/native_full.pdf"    2>/dev/null || echo N/A) bytes"
