#!/usr/bin/env bash
# measure_disk.sh — Compare Oxygen userguide PDF build: /tmp (tmpfs) vs regular dir.
#
# Workload:
#   DITA-OT 4.3.1  |  oxygenxml/userguide  |  format=pdf  |  editor-sa.ditaval
#
# Two runs are performed back-to-back on a freshly unpacked DITA-OT tree so
# that neither run benefits from OS page-cache warm-up of the other's output.
# Shared downloads (DITA-OT zip, userguide clone) are cached in SHARED_DIR and
# re-used across runs to keep download time out of measurements.
#
# Measurements per run:
#   - wall-clock build time   (python3 time.perf_counter)
#   - output directory size   (du -sb on the per-run output folder)
#   - Java temp directory size (du -sb on java.io.tmpdir; FOP intermediates)
#   - total disk consumed      (output + Java temp, in MiB)
#
# Usage:
#   bash measure_disk.sh
#   SHARED_DIR=/opt/cache bash measure_disk.sh

set -euo pipefail

# ── configuration ────────────────────────────────────────────────────────────
DITA_VER="${DITA_VER:-4.3.1}"
USERGUIDE_REPO="https://github.com/oxygenxml/userguide.git"
# Shared cache: downloaded once, read-only during builds.
SHARED_DIR="${SHARED_DIR:-/tmp/oxygen-build-shared}"
# Run 1: tmpfs — output and Java temp both inside /tmp.
TMP_RUN_DIR="/tmp/oxygen-build-tmp"
# Run 2: regular filesystem — output and Java temp under HOME.
REG_RUN_DIR="${HOME}/oxygen-build-reg"

DITAOT_DIR="${SHARED_DIR}/dita-ot-${DITA_VER}"
DITAOT_BIN="${DITAOT_DIR}/bin/dita"
USERGUIDE_DIR="${SHARED_DIR}/userguide"
DITAMAP="${USERGUIDE_DIR}/DITA/UserManual.ditamap"
DITAVAL="${USERGUIDE_DIR}/DITA/ditaval/editor-sa.ditaval"

# ── helpers ──────────────────────────────────────────────────────────────────
log()     { printf '[measure_disk] %s\n' "$*" >&2; }
ts()      { python3 -c 'import time; print(f"{time.perf_counter():.6f}")'; }
elapsed() { python3 -c "import time; print(f'{time.perf_counter()-float(\"$1\"):.3f}')"; }

# Return size in bytes (integer) of a directory, or 0 if it does not exist.
du_bytes() {
  local dir="$1"
  if [ -d "$dir" ]; then
    du -sb "$dir" | cut -f1
  else
    echo 0
  fi
}

bytes_to_mib() {
  python3 -c "print(f'{int(\"$1\") / 1048576:.1f}')"
}

# ── prerequisites ─────────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1; }

if ! need java; then
  log "Installing java ..."
  apt-get update -y >&2
  apt-get install -y default-jre-headless >&2
fi
for tool in curl unzip git python3; do
  if ! need "$tool"; then
    log "Installing ${tool} ..."
    apt-get update -y >&2
    apt-get install -y "$tool" >&2
  fi
done

JAVA_HOME_VAL=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")

# ── shared downloads (cached) ─────────────────────────────────────────────────
mkdir -p "$SHARED_DIR"

if [ ! -d "$USERGUIDE_DIR" ]; then
  log "Cloning oxygenxml/userguide (shallow) ..."
  git clone --depth 1 "$USERGUIDE_REPO" "$USERGUIDE_DIR"
fi

if [ ! -d "$DITAOT_DIR" ]; then
  log "Downloading DITA-OT ${DITA_VER} ..."
  curl -fsSL -o "${SHARED_DIR}/dita.zip" \
    "https://github.com/dita-ot/dita-ot/releases/download/${DITA_VER}/dita-ot-${DITA_VER}.zip"
  unzip -q "${SHARED_DIR}/dita.zip" -d "$SHARED_DIR"
  rm -f "${SHARED_DIR}/dita.zip"
fi

# ── run helper ────────────────────────────────────────────────────────────────
# run_build <label> <run-root>
#   <run-root>/out      — DITA-OT --output
#   <run-root>/javatmp  — java.io.tmpdir (FOP intermediates)
#   <run-root>/dita-ot  — private unpacked DITA-OT copy (avoids cache pollution)
run_build() {
  local label="$1"
  local run_root="$2"
  local out_dir="${run_root}/out"
  local java_tmp="${run_root}/javatmp"
  local dita_work="${run_root}/dita-ot"

  log "=== ${label}: preparing directories under ${run_root} ==="
  rm -rf "$run_root"
  mkdir -p "$out_dir" "$java_tmp" "$dita_work"

  # Copy a fresh DITA-OT tree so each run starts from an identical state and
  # DITA-OT's own plugin cache does not persist between runs.
  log "${label}: copying DITA-OT tree ..."
  cp -a "$DITAOT_DIR/." "$dita_work/"

  log "${label}: starting build ..."
  local T0
  T0=$(ts)

  JAVA_HOME="${JAVA_HOME_VAL}" \
  JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=${java_tmp}" \
  HOME="${run_root}" \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8 \
    "${dita_work}/bin/dita" \
      --input="$DITAMAP" \
      --format=pdf \
      --filter="$DITAVAL" \
      --output="$out_dir"

  local build_elapsed
  build_elapsed=$(elapsed "$T0")

  # ── disk measurements ───────────────────────────────────────────────────────
  local out_bytes java_bytes dita_bytes total_bytes
  out_bytes=$(du_bytes "$out_dir")
  java_bytes=$(du_bytes "$java_tmp")
  dita_bytes=$(du_bytes "$dita_work")
  total_bytes=$(( out_bytes + java_bytes + dita_bytes ))

  local out_mib java_mib dita_mib total_mib
  out_mib=$(bytes_to_mib "$out_bytes")
  java_mib=$(bytes_to_mib "$java_bytes")
  dita_mib=$(bytes_to_mib "$dita_bytes")
  total_mib=$(bytes_to_mib "$total_bytes")

  log "${label}: elapsed=${build_elapsed}s  out=${out_mib} MiB  javatmp=${java_mib} MiB  dita-ot-copy=${dita_mib} MiB  total=${total_mib} MiB"

  # Export results into global vars for the summary section.
  local pfx="${label^^}"
  pfx="${pfx//[^A-Z0-9]/_}"
  printf -v "${pfx}_SECONDS"   '%s' "$build_elapsed"
  printf -v "${pfx}_OUT_MIB"   '%s' "$out_mib"
  printf -v "${pfx}_JAVA_MIB"  '%s' "$java_mib"
  printf -v "${pfx}_DITA_MIB"  '%s' "$dita_mib"
  printf -v "${pfx}_TOTAL_MIB" '%s' "$total_mib"
}

# ── run 1: tmpfs ──────────────────────────────────────────────────────────────
run_build "TMPFS" "$TMP_RUN_DIR"

# ── run 2: regular filesystem ─────────────────────────────────────────────────
run_build "REGULAR" "$REG_RUN_DIR"

# ── summary ───────────────────────────────────────────────────────────────────
DISK_DELTA=$(python3 -c "
t=float('${TMPFS_TOTAL_MIB}')
r=float('${REGULAR_TOTAL_MIB}')
diff=r-t
sign='+' if diff>=0 else ''
print(f'{sign}{diff:.1f}')
")

printf '\n'
printf '=== RESULTS ===\n'
printf '%-30s  %8s  %10s  %10s  %12s  %10s\n' \
  "run" "time (s)" "out (MiB)" "java (MiB)" "dita-ot (MiB)" "total (MiB)"
printf '%-30s  %8s  %10s  %10s  %12s  %10s\n' \
  "Run 1 — tmpfs (/tmp)"      "${TMPFS_SECONDS}"   "${TMPFS_OUT_MIB}"   "${TMPFS_JAVA_MIB}"   "${TMPFS_DITA_MIB}"   "${TMPFS_TOTAL_MIB}"
printf '%-30s  %8s  %10s  %10s  %12s  %10s\n' \
  "Run 2 — regular (${HOME})" "${REGULAR_SECONDS}" "${REGULAR_OUT_MIB}" "${REGULAR_JAVA_MIB}" "${REGULAR_DITA_MIB}" "${REGULAR_TOTAL_MIB}"
printf '\n'
printf 'Disk delta (regular - tmpfs) : %s MiB\n' "$DISK_DELTA"
printf '\n'
printf 'TMPFS_SECONDS=%s\n'   "${TMPFS_SECONDS}"
printf 'REGULAR_SECONDS=%s\n' "${REGULAR_SECONDS}"
printf 'TMPFS_TOTAL_MIB=%s\n'   "${TMPFS_TOTAL_MIB}"
printf 'REGULAR_TOTAL_MIB=%s\n' "${REGULAR_TOTAL_MIB}"
