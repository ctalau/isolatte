#!/usr/bin/env bash
# compare.sh — Assert that the native and QEMU-produced PDFs are content-equivalent.
#
# Comparison strategy (two independent methods):
#
#   Method 1 — Metadata-normalized byte comparison:
#     Use qpdf --stream-data=uncompress to normalise internal PDF stream encoding,
#     then strip the volatile metadata dictionary entries (CreationDate, ModDate,
#     Producer, ID) with a Python script.  If the resulting byte sequences match,
#     the documents are structurally identical.
#
#   Method 2 — Visual page-level comparison:
#     Render each page of both PDFs to PNG at 150 DPI with pdftoppm, then compare
#     pixel values with sha256sum.  Identical hashes → identical visual output.
#     For any differing pages a diff image is written using ImageMagick (if
#     available) for visual inspection.
#
# Output:
#   results/comparison/summary.txt   — pass/fail verdict with detail
#   results/comparison/pages/        — rendered page PNGs for both runs
#   results/comparison/diffs/        — diff PNGs for any mismatched pages
#
# Exit codes:
#   0 — PDFs are content-equivalent (both methods agree)
#   1 — PDFs differ (at least one method reports differences)
#
# Usage:
#   ./compare.sh

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$BASE_DIR/results"
CMP_DIR="$RESULTS_DIR/comparison"
PAGES_DIR="$CMP_DIR/pages"
DIFFS_DIR="$CMP_DIR/diffs"

NATIVE_PDF="$RESULTS_DIR/native.pdf"
QEMU_PDF="$RESULTS_DIR/qemu.pdf"
SUMMARY="$CMP_DIR/summary.txt"

RENDER_DPI=150

info()    { echo "[compare] $*"; }
warn()    { echo "[compare] WARN: $*" >&2; }
die()     { echo "[compare] ERROR: $*" >&2; exit 1; }
pass()    { echo "[compare] PASS: $*"; }
fail()    { echo "[compare] FAIL: $*"; OVERALL_FAIL=1; }

OVERALL_FAIL=0

mkdir -p "$CMP_DIR" "$PAGES_DIR/native" "$PAGES_DIR/qemu" "$DIFFS_DIR"

# ── pre-flight ─────────────────────────────────────────────────────────────────
[[ -f "$NATIVE_PDF" ]] || die "results/native.pdf not found — run run_native.sh first"
[[ -f "$QEMU_PDF"   ]] || die "results/qemu.pdf not found — run run_qemu.sh first"
command -v pdftoppm >/dev/null 2>&1 || die "pdftoppm not found — run setup.sh first"
command -v qpdf     >/dev/null 2>&1 || die "qpdf not found — run setup.sh first"

HAS_CONVERT=0
command -v convert >/dev/null 2>&1 && HAS_CONVERT=1 || warn "ImageMagick 'convert' not found; diff images will be skipped"

info "Native PDF : $NATIVE_PDF  ($(stat -c%s "$NATIVE_PDF") bytes)"
info "QEMU PDF   : $QEMU_PDF  ($(stat -c%s "$QEMU_PDF") bytes)"

# ── Method 1: metadata-normalised byte comparison ──────────────────────────────
info "Method 1: metadata-normalised byte comparison"

NATIVE_NORM="$CMP_DIR/native_normalised.pdf"
QEMU_NORM="$CMP_DIR/qemu_normalised.pdf"

# Step 1a: uncompress all streams so content is in canonical form
qpdf --stream-data=uncompress "$NATIVE_PDF" "$NATIVE_NORM"
qpdf --stream-data=uncompress "$QEMU_PDF"   "$QEMU_NORM"

# Step 1b: strip volatile metadata fields using Python
# CreationDate, ModDate, Producer, and the file ID pair are set at build time
# and are therefore legitimately different between two separate runs.
python3 - "$NATIVE_NORM" "$CMP_DIR/native_stripped.pdf" <<'PYEOF'
import sys, re

with open(sys.argv[1], 'rb') as f:
    data = f.read()

# Strip /CreationDate, /ModDate, /Producer, /ID entries and the two-element
# file ID array at the end of the xref trailer.  These are the only fields
# that legitimately differ between bit-for-bit identical document content.
patterns = [
    rb'/CreationDate\s*\([^)]*\)',
    rb'/ModDate\s*\([^)]*\)',
    rb'/Producer\s*\([^)]*\)',
    rb'/ID\s*\[<[0-9A-Fa-f]*>\s*<[0-9A-Fa-f]*>\]',
    rb'/ID\s*\[<[0-9A-Fa-f\s]*>\s*<[0-9A-Fa-f\s]*>\]',
]
for pat in patterns:
    data = re.sub(pat, b'', data)

with open(sys.argv[2], 'wb') as f:
    f.write(data)
PYEOF

python3 - "$QEMU_NORM" "$CMP_DIR/qemu_stripped.pdf" <<'PYEOF'
import sys, re

with open(sys.argv[1], 'rb') as f:
    data = f.read()

patterns = [
    rb'/CreationDate\s*\([^)]*\)',
    rb'/ModDate\s*\([^)]*\)',
    rb'/Producer\s*\([^)]*\)',
    rb'/ID\s*\[<[0-9A-Fa-f]*>\s*<[0-9A-Fa-f]*>\]',
    rb'/ID\s*\[<[0-9A-Fa-f\s]*>\s*<[0-9A-Fa-f\s]*>\]',
]
for pat in patterns:
    data = re.sub(pat, b'', data)

with open(sys.argv[2], 'wb') as f:
    f.write(data)
PYEOF

NATIVE_STRIPPED_SHA=$(sha256sum "$CMP_DIR/native_stripped.pdf" | awk '{print $1}')
QEMU_STRIPPED_SHA=$(sha256sum "$CMP_DIR/qemu_stripped.pdf"   | awk '{print $1}')

info "  native stripped SHA-256 : $NATIVE_STRIPPED_SHA"
info "  qemu   stripped SHA-256 : $QEMU_STRIPPED_SHA"

METHOD1_RESULT="FAIL"
if [[ "$NATIVE_STRIPPED_SHA" == "$QEMU_STRIPPED_SHA" ]]; then
  METHOD1_RESULT="PASS"
  pass "Method 1: byte-identical after metadata strip"
else
  fail "Method 1: byte content differs after metadata strip"
fi

# ── Method 2: visual page-level comparison ─────────────────────────────────────
info "Method 2: visual page-level comparison at ${RENDER_DPI} DPI"

# Get page counts
NATIVE_PAGES=$(pdfinfo "$NATIVE_PDF" 2>/dev/null | grep '^Pages:' | awk '{print $2}')
QEMU_PAGES=$(pdfinfo   "$QEMU_PDF"   2>/dev/null | grep '^Pages:' | awk '{print $2}')

info "  Native pages : $NATIVE_PAGES"
info "  QEMU pages   : $QEMU_PAGES"

PAGE_COUNT_MATCH="PASS"
if [[ "$NATIVE_PAGES" != "$QEMU_PAGES" ]]; then
  fail "Method 2: page count mismatch ($NATIVE_PAGES vs $QEMU_PAGES)"
  PAGE_COUNT_MATCH="FAIL"
else
  pass "Method 2: page counts match ($NATIVE_PAGES pages)"
fi

# Render pages (only if page counts match — otherwise comparison is undefined)
PAGES_MATCH=0
PAGES_DIFFER=0
PAGES_COMPARED=0
METHOD2_RESULT="SKIP"

if [[ "$PAGE_COUNT_MATCH" == "PASS" ]]; then
  info "  Rendering pages to PNG at ${RENDER_DPI} DPI..."
  pdftoppm -r "$RENDER_DPI" -png "$NATIVE_PDF" "$PAGES_DIR/native/page"
  pdftoppm -r "$RENDER_DPI" -png "$QEMU_PDF"   "$PAGES_DIR/qemu/page"

  # Compare page by page
  DIFF_PAGES=()
  while IFS= read -r native_page; do
    page_num=$(basename "$native_page" | sed 's/page-\{0,1\}\([0-9]*\)\.png/\1/')
    # Handle both "page-001.png" and "page001.png" naming
    qemu_page="$PAGES_DIR/qemu/$(basename "$native_page")"
    if [[ ! -f "$qemu_page" ]]; then
      qemu_page=$(find "$PAGES_DIR/qemu" -name "*${page_num}*.png" | head -1)
    fi

    if [[ -z "$qemu_page" || ! -f "$qemu_page" ]]; then
      warn "  No matching QEMU page for $native_page — skipping"
      continue
    fi

    PAGES_COMPARED=$(( PAGES_COMPARED + 1 ))
    native_sha=$(sha256sum "$native_page" | awk '{print $1}')
    qemu_sha=$(sha256sum   "$qemu_page"   | awk '{print $1}')

    if [[ "$native_sha" == "$qemu_sha" ]]; then
      PAGES_MATCH=$(( PAGES_MATCH + 1 ))
    else
      PAGES_DIFFER=$(( PAGES_DIFFER + 1 ))
      DIFF_PAGES+=("$page_num")
      # Generate a visual diff if ImageMagick is available
      if [[ "$HAS_CONVERT" -eq 1 ]]; then
        DIFF_IMG="$DIFFS_DIR/diff_page${page_num}.png"
        convert "$native_page" "$qemu_page" \
          -compose Difference -composite \
          -negate \
          "$DIFF_IMG" 2>/dev/null || true
      fi
    fi
  done < <(find "$PAGES_DIR/native" -name "*.png" | sort)

  info "  Pages compared  : $PAGES_COMPARED"
  info "  Pages identical : $PAGES_MATCH"
  info "  Pages differing : $PAGES_DIFFER"

  if [[ "$PAGES_DIFFER" -gt 0 ]]; then
    fail "Method 2: $PAGES_DIFFER of $PAGES_COMPARED pages differ visually (pages: ${DIFF_PAGES[*]})"
    METHOD2_RESULT="FAIL"
  else
    pass "Method 2: all $PAGES_COMPARED pages are pixel-identical"
    METHOD2_RESULT="PASS"
  fi
fi

# ── verdict ────────────────────────────────────────────────────────────────────
info ""
info "═══════════════════════════════════════"
info " VERDICT"
info "═══════════════════════════════════════"
info " Method 1 (byte comparison) : $METHOD1_RESULT"
info " Method 2 (visual render)   : $METHOD2_RESULT"

VERDICT="PASS"
if [[ "$METHOD1_RESULT" == "FAIL" || "$METHOD2_RESULT" == "FAIL" ]]; then
  VERDICT="FAIL"
fi
info " Overall                    : $VERDICT"
info "═══════════════════════════════════════"

# ── write summary ──────────────────────────────────────────────────────────────
{
  echo "PDF Content Equivalence Report"
  echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo ""
  echo "Input PDFs:"
  echo "  native : $NATIVE_PDF"
  echo "  qemu   : $QEMU_PDF"
  echo ""
  echo "Method 1 — Metadata-normalised byte comparison:"
  echo "  native SHA-256 (stripped): $NATIVE_STRIPPED_SHA"
  echo "  qemu   SHA-256 (stripped): $QEMU_STRIPPED_SHA"
  echo "  Result: $METHOD1_RESULT"
  echo ""
  echo "Method 2 — Visual page-level comparison (${RENDER_DPI} DPI):"
  echo "  Page count native : $NATIVE_PAGES"
  echo "  Page count qemu   : $QEMU_PAGES"
  echo "  Pages compared    : $PAGES_COMPARED"
  echo "  Pages identical   : $PAGES_MATCH"
  echo "  Pages differing   : $PAGES_DIFFER"
  echo "  Result            : $METHOD2_RESULT"
  echo ""
  echo "OVERALL VERDICT: $VERDICT"
} | tee "$SUMMARY"

[[ "$VERDICT" == "PASS" ]] && exit 0 || exit 1
