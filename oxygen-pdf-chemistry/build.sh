#!/usr/bin/env bash
# build.sh — Download DITA sources + Oxygen PDF Chemistry, build the
#            oxygenxml/userguide as a PDF, and analyze per-step timing/RAM.
#
# All heavy lifting is done by run_analysis.py.
#
# Usage:
#   bash build.sh
#   WORKDIR=/my/dir bash build.sh

set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/oxygen-chemistry-pdf}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec python3 "${SCRIPT_DIR}/run_analysis.py" --workdir "${WORKDIR}"
