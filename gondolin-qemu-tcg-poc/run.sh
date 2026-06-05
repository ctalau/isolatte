#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── dependency checks ──────────────────────────────────────────────────────────

if ! command -v qemu-system-x86_64 &>/dev/null; then
  echo "ERROR: qemu-system-x86_64 not found." >&2
  echo "  Install: sudo apt-get install -y qemu-system-x86 qemu-utils" >&2
  exit 1
fi

if ! command -v node &>/dev/null; then
  echo "ERROR: node not found. Install Node.js 18+." >&2
  exit 1
fi

NODE_MAJOR=$(node --version | sed 's/v\([0-9]*\).*/\1/')
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "ERROR: Node.js 18+ required (found $(node --version))." >&2
  exit 1
fi

# ── npm install ────────────────────────────────────────────────────────────────

cd "$SCRIPT_DIR"

if [ ! -d node_modules ]; then
  echo "[run.sh] Installing npm dependencies..."
  npm ci
fi

# ── run ────────────────────────────────────────────────────────────────────────

echo "[run.sh] Starting gondolin-qemu-tcg-poc (TCG mode, no /dev/kvm needed)..."
echo "[run.sh] Gondolin guest image (~98 MB) will be downloaded on first run if not cached."
echo ""

exec node poc.mjs
