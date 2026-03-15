#!/usr/bin/env bash
# benchmark.sh — Index DITA topics and run search queries with timing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
QMD="bun $SCRIPT_DIR/qmd-tool/src/cli/qmd.ts"
DITA_DIR="$SCRIPT_DIR/oxygenxml-userguide/DITA"
COLLECTION_NAME="oxygenxml-userguide"
INDEX_DB="${XDG_CACHE_HOME:-$HOME/.cache}/qmd/index.sqlite"
RESULTS_FILE="$SCRIPT_DIR/results.txt"

# Use node if bun not available
if ! command -v bun &>/dev/null; then
  QMD="npx tsx $SCRIPT_DIR/qmd-tool/src/cli/qmd.ts"
fi

echo "QMD DITA Indexing Benchmark" | tee "$RESULTS_FILE"
echo "==========================" | tee -a "$RESULTS_FILE"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Count DITA files
DITA_COUNT=$(find "$DITA_DIR" -name "*.dita" | wc -l)
echo "DITA topics found: $DITA_COUNT" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Remove existing collection if present
$QMD collection remove "$COLLECTION_NAME" 2>/dev/null || true

# --- Indexing benchmark ---
echo "=== INDEXING ===" | tee -a "$RESULTS_FILE"
INDEX_START=$(date +%s%N)
$QMD collection add "$DITA_DIR" --name "$COLLECTION_NAME" --mask '**/*.dita' 2>&1 | tee -a "$RESULTS_FILE"
INDEX_END=$(date +%s%N)
INDEX_MS=$(( (INDEX_END - INDEX_START) / 1000000 ))
echo "" | tee -a "$RESULTS_FILE"
echo "Indexing time: ${INDEX_MS}ms" | tee -a "$RESULTS_FILE"

# Index size
INDEX_SIZE=$(ls -lh "$INDEX_DB" | awk '{print $5}')
INDEX_SIZE_BYTES=$(stat -c%s "$INDEX_DB")
echo "Index size: $INDEX_SIZE ($INDEX_SIZE_BYTES bytes)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# --- Search benchmarks ---
echo "=== SEARCH QUERIES ===" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

run_search() {
  local label="$1"
  local query="$2"
  local extra_args="${3:-}"

  echo "--- $label ---" | tee -a "$RESULTS_FILE"
  echo "Query: \"$query\"" | tee -a "$RESULTS_FILE"

  SEARCH_START=$(date +%s%N)
  RESULT=$($QMD search "$query" --json -n 10 $extra_args 2>&1)
  SEARCH_END=$(date +%s%N)
  SEARCH_MS=$(( (SEARCH_END - SEARCH_START) / 1000000 ))

  echo "Time: ${SEARCH_MS}ms" | tee -a "$RESULTS_FILE"
  echo "Results:" | tee -a "$RESULTS_FILE"
  echo "$RESULT" | tee -a "$RESULTS_FILE"
  echo "" | tee -a "$RESULTS_FILE"
}

# Query 1: Full natural-language question
run_search "Full NL query" \
  "How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion"

# Query 2: Extracted keywords
run_search "Keyword query" \
  "enable Oxygen Feedback webhelp Content Fusion"

# Query 3: Focused keyword search
run_search "Focused query" \
  "webhelp feedback integration"

# Query 4: Targeted query for the answer
run_search "Targeted query" \
  "Oxygen Feedback site configuration webhelp transformation"

echo "=== DONE ===" | tee -a "$RESULTS_FILE"
echo "Full results saved to: $RESULTS_FILE"
