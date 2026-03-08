#!/usr/bin/env bash
# benchmark_pdf.sh — Measure Oxygen XML Editor PDF user-guide build time
# inside the nsjail sandbox vs. natively (no sandbox).
#
# Workload:
#   DITA-OT 4.3.1  |  oxygenxml/userguide  |  format=pdf  |  editor-sa.ditaval
#
# nsjail isolation layers (all active):
#   clone_newns   — chroot to minimal rootfs with bind-mounted DITA tree
#   clone_newnet  — new network namespace, no external connectivity
#   clone_newpid  — isolated PID tree
#   clone_newuts  — isolated hostname
#   clone_newipc  — isolated IPC objects
#   clone_newuser — UID 1000 inside mapped to calling user
#   keep_caps:false — all capabilities dropped
#
# Constraint: in Docker/OCI containers without CAP_SYS_ADMIN, read-only
# remounts of bind mounts are blocked by the kernel.  The bind mounts in the
# sandboxed run are therefore writable.  All namespace layers remain active.
#
# Prerequisites (installed by the script when missing):
#   nsjail (must be pre-built — not available as a package on Ubuntu 24.04)
#   uidmap, java
#
# Usage:
#   bash benchmark_pdf.sh
#   WORKDIR=/my/dir bash benchmark_pdf.sh

set -euo pipefail

WORKDIR="${WORKDIR:-/tmp/oxygen-nsjail-pdf}"
DITA_VER="${DITA_VER:-4.3.1}"
USERGUIDE_REPO="https://github.com/oxygenxml/userguide.git"

DITA_BIN="${WORKDIR}/dita-ot-${DITA_VER}/bin/dita"
USERGUIDE_DIR="${WORKDIR}/userguide"
DITAMAP="${USERGUIDE_DIR}/DITA/UserManual.ditamap"
DITAVAL="${USERGUIDE_DIR}/DITA/ditaval/editor-sa.ditaval"
OUT_NATIVE="${WORKDIR}/out-native"
OUT_NSJAIL="${WORKDIR}/out-nsjail"

log() { printf '[benchmark] %s\n' "$*" >&2; }

# ── prerequisites ─────────────────────────────────────────────────────────────
if ! command -v nsjail >/dev/null 2>&1; then
  log "nsjail not found — build from https://github.com/google/nsjail and put it on PATH"
  exit 1
fi
if ! command -v java >/dev/null 2>&1; then
  apt-get install -y default-jre-headless >&2
fi
if ! command -v newuidmap >/dev/null 2>&1; then
  apt-get install -y uidmap >&2
fi

JAVA_HOME_VAL=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")

# ── fetch sources ─────────────────────────────────────────────────────────────
mkdir -p "$WORKDIR"

if [ ! -d "$USERGUIDE_DIR" ]; then
  log "Cloning oxygenxml/userguide ..."
  git clone --depth 1 "$USERGUIDE_REPO" "$USERGUIDE_DIR"
fi

if [ ! -d "${WORKDIR}/dita-ot-${DITA_VER}" ]; then
  log "Downloading DITA-OT ${DITA_VER} ..."
  curl -fsSL -o "${WORKDIR}/dita.zip" \
    "https://github.com/dita-ot/dita-ot/releases/download/${DITA_VER}/dita-ot-${DITA_VER}.zip"
  unzip -q "${WORKDIR}/dita.zip" -d "$WORKDIR"
fi

ts()      { python3 -c 'import time; print(f"{time.perf_counter():.6f}")'; }
elapsed() { python3 -c "import time; print(f'{time.perf_counter()-float(\"$1\"):.3f}')"; }

# ── run 1: native (no sandbox) ────────────────────────────────────────────────
log "=== Run 1: native (no sandbox) ==="
rm -rf "$OUT_NATIVE"
mkdir -p "$OUT_NATIVE"

T0=$(ts)
"$DITA_BIN" \
  --input="$DITAMAP" \
  --format=pdf \
  --filter="$DITAVAL" \
  --output="$OUT_NATIVE"
NATIVE_ELAPSED=$(elapsed "$T0")

log "Native elapsed : ${NATIVE_ELAPSED}s"
NATIVE_PDF=$(find "$OUT_NATIVE" -name "*.pdf" | head -1)
log "Native PDF     : ${NATIVE_PDF:-<not found>}"

# ── run 2: nsjail sandbox ─────────────────────────────────────────────────────
log "=== Run 2: nsjail sandbox ==="
rm -rf "$OUT_NSJAIL"
mkdir -p "$OUT_NSJAIL"

HOST_UID=$(id -u)
HOST_GID=$(id -g)

ROOTFS=$(mktemp -d /tmp/dita-nsjail-bench-XXXXXX)
cleanup() { rm -rf "$ROOTFS"; }
trap cleanup EXIT

mkdir -p "${ROOTFS}"/{proc,sys,dev,tmp,etc,home,opt}
for d in /usr /bin /sbin /lib /lib64; do
  [ -d "$d" ] && mkdir -p "${ROOTFS}${d}"
done
mkdir -p "${ROOTFS}/opt/work"
mkdir -p "${ROOTFS}/opt/output"
# Java reads its security config from /etc/java-*-openjdk/
for d in /etc/java-*-openjdk; do
  [ -d "$d" ] && mkdir -p "${ROOTFS}${d}"
done

T0=$(ts)

# Inside the jail:
#   /opt/work    — DITA-OT + userguide (bind, writable; RO remount blocked by container)
#   /opt/output  — PDF output (bind, writable)
#   /tmp         — tmpfs 2 GiB (DITA-OT FOP writes ~500 MiB of intermediates here)
#   /dev         — tmpfs 4 MiB
#   /proc        — procfs (auto-mounted by nsjail)
#
# All five namespace clones are on by default in this nsjail build:
#   clone_newnet, clone_newns, clone_newpid, clone_newuts, clone_newipc
# User namespace is explicit via --uid_mapping / --gid_mapping.

BIND_JAVA_ETC=()
for d in /etc/java-*-openjdk; do
  [ -d "$d" ] && BIND_JAVA_ETC+=("-B" "${d}:${d}")
done

nsjail \
  -Mo \
  --log_fd 2 \
  --time_limit 900 \
  --chroot "${ROOTFS}" \
  --rw \
  \
  -B "${WORKDIR}:/opt/work" \
  -B "${OUT_NSJAIL}:/opt/output" \
  \
  -B /usr:/usr \
  -B /bin:/bin \
  -B /sbin:/sbin \
  -B /lib:/lib \
  -B /lib64:/lib64 \
  \
  -B /etc/ld.so.cache:/etc/ld.so.cache \
  -B /etc/ld.so.conf.d:/etc/ld.so.conf.d \
  -B /etc/nsswitch.conf:/etc/nsswitch.conf \
  -B /etc/passwd:/etc/passwd \
  -B /etc/group:/etc/group \
  "${BIND_JAVA_ETC[@]}" \
  \
  -m "none:/tmp:tmpfs:size=2147483648" \
  -m "none:/dev:tmpfs:size=4194304" \
  \
  -D "/opt/work" \
  --uid_mapping "1000:${HOST_UID}:1" \
  --gid_mapping "1000:${HOST_GID}:1" \
  --disable_rlimits \
  \
  -E "HOME=/tmp" \
  -E "LANG=C.UTF-8" \
  -E "LC_ALL=C.UTF-8" \
  -E "JAVA_HOME=${JAVA_HOME_VAL}" \
  -E "JAVA_TOOL_OPTIONS=-Djava.io.tmpdir=/tmp" \
  -E "PATH=/usr/bin:/bin:/usr/local/bin" \
  \
  -- \
  "/opt/work/dita-ot-${DITA_VER}/bin/dita" \
    --input="/opt/work/userguide/DITA/UserManual.ditamap" \
    --format=pdf \
    --filter="/opt/work/userguide/DITA/ditaval/editor-sa.ditaval" \
    --output="/opt/output"

NSJAIL_ELAPSED=$(elapsed "$T0")

log "nsjail elapsed : ${NSJAIL_ELAPSED}s"
NSJAIL_PDF=$(find "$OUT_NSJAIL" -name "*.pdf" | head -1)
log "nsjail PDF     : ${NSJAIL_PDF:-<not found>}"

# ── summary ───────────────────────────────────────────────────────────────────
OVERHEAD=$(python3 -c "
native=float('${NATIVE_ELAPSED}')
ns=float('${NSJAIL_ELAPSED}')
pct=(ns-native)/native*100
print(f'{pct:+.1f}%')
")

printf '\n'
printf '=== RESULTS ===\n'
printf 'Native (no sandbox) : %ss\n' "$NATIVE_ELAPSED"
printf 'nsjail sandbox      : %ss\n' "$NSJAIL_ELAPSED"
printf 'Overhead            : %s\n'  "$OVERHEAD"
printf 'NATIVE_SECONDS=%s\n'  "$NATIVE_ELAPSED"
printf 'NSJAIL_SECONDS=%s\n'  "$NSJAIL_ELAPSED"
