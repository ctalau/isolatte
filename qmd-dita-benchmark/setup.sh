#!/usr/bin/env bash
# setup.sh — Clone repos and install qmd for DITA indexing benchmark
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Step 1: Clone qmd ==="
if [ ! -d "$SCRIPT_DIR/qmd-tool" ]; then
  git clone https://github.com/tobi/qmd.git "$SCRIPT_DIR/qmd-tool"
else
  echo "qmd-tool already cloned, skipping"
fi

echo "=== Step 2: Clone oxygenxml/userguide ==="
if [ ! -d "$SCRIPT_DIR/oxygenxml-userguide" ]; then
  git clone --depth 1 https://github.com/oxygenxml/userguide.git "$SCRIPT_DIR/oxygenxml-userguide"
else
  echo "oxygenxml-userguide already cloned, skipping"
fi

echo "=== Step 3: Install qmd dependencies ==="
cd "$SCRIPT_DIR/qmd-tool"
if command -v bun &>/dev/null; then
  bun install
else
  npm install
fi

echo "=== Step 4: Build qmd ==="
if command -v bun &>/dev/null; then
  bun run build
else
  npm run build
fi

echo ""
echo "Setup complete. Run ./benchmark.sh to index and search."
