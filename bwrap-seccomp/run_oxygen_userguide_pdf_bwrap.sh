#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${WORKDIR:-/tmp/oxygen-bwrap-pdf}"
DITA_VER="${DITA_VER:-4.3.1}"
USERGUIDE_REPO="https://github.com/oxygenxml/userguide.git"
FILTER_FILE="/tmp/bwrap_pdf_seccomp_$$.bpf"

cleanup() {
  rm -f "$FILTER_FILE"
}
trap cleanup EXIT

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd bwrap || ! need_cmd gcc || ! need_cmd git || ! need_cmd curl || ! need_cmd unzip; then
  apt-get update -y
  apt-get install -y bubblewrap gcc git curl unzip
fi

if [ ! -f /usr/include/seccomp.h ]; then
  apt-get update -y
  apt-get install -y libseccomp-dev
fi

if ! need_cmd java; then
  apt-get update -y
  apt-get install -y default-jre-headless
fi

if [ ! -x "${SCRIPT_DIR}/gen_seccomp" ]; then
  gcc -O2 -o "${SCRIPT_DIR}/gen_seccomp" "${SCRIPT_DIR}/gen_seccomp.c" -lseccomp
fi

mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [ ! -d userguide ]; then
  git clone --depth 1 "$USERGUIDE_REPO" userguide
fi

if [ ! -d "dita-ot-${DITA_VER}" ]; then
  curl -L -o dita.zip "https://github.com/dita-ot/dita-ot/releases/download/${DITA_VER}/dita-ot-${DITA_VER}.zip"
  unzip -q dita.zip
fi

"${SCRIPT_DIR}/gen_seccomp" "$FILTER_FILE"
exec {SECCOMP_FD}<"$FILTER_FILE"

for fd in $(ls /proc/self/fd 2>/dev/null | sort -n); do
  if [ "$fd" -gt 2 ] && [ "$fd" -ne "$SECCOMP_FD" ]; then
    eval "exec ${fd}>&-" 2>/dev/null || true
  fi
done

rm -rf "$WORKDIR/out-bwrap-pdf"
mkdir -p "$WORKDIR/out-bwrap-pdf"

START_TS=$(python3 - <<'PY'
import time
print(f"{time.perf_counter():.6f}")
PY
)

bwrap \
  --unshare-user-try \
  --uid 65534 \
  --gid 65534 \
  --unshare-ipc \
  --unshare-uts \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --ro-bind /etc /etc \
  --ro-bind "$WORKDIR" /work \
  --bind "$WORKDIR/out-bwrap-pdf" /output \
  --ro-bind /proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --new-session \
  --die-with-parent \
  --clearenv \
  --setenv PATH /usr/bin:/bin \
  --setenv HOME /tmp \
  --setenv LANG C.UTF-8 \
  --setenv LC_ALL C.UTF-8 \
  --setenv JAVA_TOOL_OPTIONS -Djava.io.tmpdir=/tmp \
  --chdir /tmp \
  --cap-drop ALL \
  --add-seccomp-fd "$SECCOMP_FD" \
  -- /work/dita-ot-${DITA_VER}/bin/dita \
      --input=/work/userguide/DITA/UserManual.ditamap \
      --format=pdf \
      --filter=/work/userguide/DITA/ditaval/editor-sa.ditaval \
      --output=/output

ELAPSED=$(python3 - <<PY
import time
start=float("$START_TS")
print(f"{time.perf_counter()-start:.3f}")
PY
)

printf 'BWRAP_PDF_REAL_SECONDS=%s\n' "$ELAPSED"
printf 'PDF output directory: %s\n' "$WORKDIR/out-bwrap-pdf"
