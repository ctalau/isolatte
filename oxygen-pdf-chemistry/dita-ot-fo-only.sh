#!/usr/bin/env bash
# dita-ot-fo-only.sh — Run the DITA-OT PDF pipeline, keep the temp
# directory, and copy the generated XSL-FO file (topic.fo) to the
# current directory.  The FO file is the sole input to FOP (fop.sh).
#
# Usage:
#   bash dita-ot-fo-only.sh
#   WORKDIR=/my/dir bash dita-ot-fo-only.sh

set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/oxygen-chemistry-pdf}"
DITA_OT="${DITA_OT:-${WORKDIR}/dita-ot-4.3.1}"
DITAMAP="${DITAMAP:-${WORKDIR}/userguide/DITA/UserManual.ditamap}"
DITAVAL="${DITAVAL:-${WORKDIR}/userguide/DITA/ditaval/editor-sa.ditaval}"
OUT_DIR="${WORKDIR}/output-fo-stage"
TEMP_DIR="${WORKDIR}/tmp-fo-stage"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '[fo-stage] %s\n' "$*" >&2; }

if [ ! -f "${DITA_OT}/bin/dita" ]; then
  log "ERROR: DITA-OT not found at ${DITA_OT}"
  log "Run python3 run_analysis.py first, or set DITA_OT="
  exit 1
fi

JAVA_HOME_VAL=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")

log "=== Running DITA-OT (Build FO + Format PDF) keeping temp dir ==="
log "Input  : $DITAMAP"
log "Temp   : $TEMP_DIR"

rm -rf "$TEMP_DIR" "$OUT_DIR"
mkdir -p "$OUT_DIR"

T0=$(python3 -c 'import time; print(f"{time.perf_counter():.6f}")')

JAVA_HOME="$JAVA_HOME_VAL" "${DITA_OT}/bin/dita" \
  --input="$DITAMAP" \
  --format=pdf \
  --filter="$DITAVAL" \
  --output="$OUT_DIR" \
  -t "$TEMP_DIR" \
  -Dclean.temp=no \
  2>&1

ELAPSED=$(python3 -c "import time; print(f'{time.perf_counter()-float(\"$T0\"):.1f}')")
log "Build completed in ${ELAPSED}s"

FO_SRC="${TEMP_DIR}/topic.fo"
if [ ! -f "$FO_SRC" ]; then
  log "ERROR: topic.fo not found at $FO_SRC"
  log "Temp dir contents:"
  ls "$TEMP_DIR" | head -20
  exit 1
fi

FO_SIZE=$(du -sh "$FO_SRC" | cut -f1)
log "topic.fo : $FO_SRC ($FO_SIZE)"

# Copy to the experiment directory for committing / reuse
cp "$FO_SRC" "${SCRIPT_DIR}/topic.fo"
log "Copied  -> ${SCRIPT_DIR}/topic.fo"
