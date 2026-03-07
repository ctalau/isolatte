#!/usr/bin/env bash
# sandbox_dita.sh (hardened) — run a command inside an nsjail sandbox that
# exposes only the DITA project, with strict resource caps and loopback-only
# networking.
#
# See ESCAPE_ANALYSIS.md for the full list of escape vectors this version closes.
#
# Isolation layers (outermost → innermost):
#   prlimit   — AS (1 GiB), nproc (256), cpu-time (1 h), fsize (512 MiB)
#   taskset   — pin the whole subtree to one CPU core
#   nsjail    — mount + net + pid + ipc + uts + user namespaces;
#               chroot to a minimal per-run rootfs;
#               seccomp deny-list (seccomp.policy);
#               full capability drop
#   inner.sh  — re-mounts /tmp with a 128 MiB cap, brings up loopback,
#               starts python http.server on 127.0.0.1 only, then execs
#               the user command
#
# Prerequisites:
#   sudo apt-get install nsjail util-linux
#
# Usage:
#   ./sandbox_dita.sh [OPTIONS] -- COMMAND [ARGS...]
#   DITA_PROJECT=/data/myproject ./sandbox_dita.sh -- dita-ot.sh build
#
# Options:
#   --dita-project PATH   DITA project root   (env DITA_PROJECT,  default /opt/dita-ot)
#   --http-port    PORT   HTTP server port     (env HTTP_PORT,     default 8000)
#   --cpu-core     N      CPU core to pin to   (env CPU_CORE,      default 0)
#   --mem-limit    MiB    Address-space cap    (env MEM_LIMIT_MiB, default 1024)
#   --time-limit   SEC    Wall-clock timeout   (env TIME_LIMIT,    default 86400)
#   -h, --help

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
DITA_PROJECT="${DITA_PROJECT:-/opt/dita-ot}"
HTTP_PORT="${HTTP_PORT:-8000}"
CPU_CORE="${CPU_CORE:-0}"
MEM_LIMIT_MiB="${MEM_LIMIT_MiB:-1024}"
TIME_LIMIT="${TIME_LIMIT:-86400}"

# Directory containing this script — used to locate seccomp.policy.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[sandbox] $*" >&2; }

usage() {
  sed -n '/^# Usage:/,/^[^#]/{ s/^# \{0,1\}//; /^[^#]/d; p }' "$0" >&2
  exit 1
}

# ── argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dita-project) DITA_PROJECT="$2"; shift 2 ;;
    --http-port)    HTTP_PORT="$2";    shift 2 ;;
    --cpu-core)     CPU_CORE="$2";     shift 2 ;;
    --mem-limit)    MEM_LIMIT_MiB="$2"; shift 2 ;;
    --time-limit)   TIME_LIMIT="$2";   shift 2 ;;
    -h|--help)      usage ;;
    --)             shift; break ;;
    *) die "Unknown option: $1  (run with --help)" ;;
  esac
done
[[ $# -gt 0 ]] || die "No command specified after '--'  (run with --help)"

# ── validation ────────────────────────────────────────────────────────────────
[[ "$MEM_LIMIT_MiB" =~ ^[0-9]+$ ]] || die "--mem-limit must be a positive integer"
[[ "$CPU_CORE"      =~ ^[0-9]+$ ]] || die "--cpu-core must be a non-negative integer"
[[ "$TIME_LIMIT"    =~ ^[0-9]+$ ]] || die "--time-limit must be a non-negative integer"

command -v nsjail  >/dev/null 2>&1 || die "nsjail not found  (sudo apt-get install nsjail)"
command -v prlimit >/dev/null 2>&1 || die "prlimit not found (sudo apt-get install util-linux)"
command -v taskset >/dev/null 2>&1 || die "taskset not found (sudo apt-get install util-linux)"
command -v python3 >/dev/null 2>&1 || die "python3 not found"

SECCOMP_POLICY="${SCRIPT_DIR}/seccomp.policy"
[[ -f "$SECCOMP_POLICY" ]] || die "seccomp.policy not found at: $SECCOMP_POLICY"

# ── E-14: canonicalize and allowlist-check the DITA project path ──────────────
# Resolve symlinks so a path like /tmp/link -> /etc never slips through.
DITA_PROJECT="$(realpath --canonicalize-existing "$DITA_PROJECT" 2>/dev/null \
  || die "DITA project path not found or not accessible: $DITA_PROJECT")"
[[ -d "$DITA_PROJECT" ]] || die "DITA project is not a directory: $DITA_PROJECT"

# Reject obviously sensitive host paths.  Extend this list as needed.
for BLOCKED in /etc /proc /sys /root /boot /dev /run /var/run; do
  [[ "$DITA_PROJECT" == "$BLOCKED" || "$DITA_PROJECT" == "$BLOCKED/"* ]] \
    && die "Refusing to sandbox a sensitive host path: $DITA_PROJECT"
done

MEM_LIMIT_BYTES=$(( MEM_LIMIT_MiB * 1024 * 1024 ))
FSIZE_BYTES=$(( 512 * 1024 * 1024 ))   # 512 MiB max single file

info "DITA project  : $DITA_PROJECT"
info "CPU core      : $CPU_CORE"
info "Memory limit  : ${MEM_LIMIT_MiB} MiB"
info "Wall-clock    : ${TIME_LIMIT} s"
info "HTTP port     : $HTTP_PORT"
info "Command       : $*"

# ── E-11: build minimal rootfs in a mode-700 directory ───────────────────────
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"

ROOTFS="${WORK_DIR}/rootfs"
mkdir -p "$ROOTFS"

# ── E-10: inner wrapper in a secure subdirectory, mode 500 ───────────────────
SCRIPTS_DIR="${WORK_DIR}/scripts"
mkdir -p "$SCRIPTS_DIR"
chmod 700 "$SCRIPTS_DIR"
INNER_SCRIPT="${SCRIPTS_DIR}/inner.sh"

# ── E-19: synthetic minimal /etc — no real host metadata exposed ──────────────
ETC_DIR="${WORK_DIR}/etc"
mkdir -p "$ETC_DIR"
# Only two entries: root (for tools that require it) and nobody (runtime UID).
printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' \
  > "${ETC_DIR}/passwd"
printf 'root:x:0:\nnobody:x:65534:\n' \
  > "${ETC_DIR}/group"
# Empty resolv.conf — DNS is unreachable with loopback-only networking.
: > "${ETC_DIR}/resolv.conf"
chmod 444 "${ETC_DIR}/passwd" "${ETC_DIR}/group" "${ETC_DIR}/resolv.conf"

cleanup() {
  local d
  for d in proc sys dev tmp run; do
    mountpoint -q "${ROOTFS}/${d}" 2>/dev/null && umount -l "${ROOTFS}/${d}" || true
  done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Create the mountpoint skeleton inside the rootfs.  Real content comes from
# bind mounts; these directories just need to exist.
mkdir -p "$ROOTFS"/{proc,sys,dev,tmp,run,etc,home}
mkdir -p "$ROOTFS$DITA_PROJECT"   # target for the DITA bind mount

# ── E-01 / E-19: inner wrapper script ─────────────────────────────────────────
# Runs as PID 1 inside the jail (root within the user namespace).
# 1. Re-mounts /tmp with a hard size cap            (fixes E-05)
# 2. Masks dangerous /proc entries with /dev/null   (fixes E-01)
# 3. Brings up loopback (safe: scoped to the jail's net namespace)
# 4. Starts python http.server on 127.0.0.1 only
# 5. exec's the user command
cat > "$INNER_SCRIPT" <<INNER_EOF
#!/bin/sh
set -e

# ── E-05: cap /tmp at 128 MiB ────────────────────────────────────────────────
# CAP_SYS_ADMIN is available here because we are UID 0 inside our own
# mount namespace (user namespace).  It cannot affect the host.
mount -o remount,size=128m /tmp 2>/dev/null || true

# ── E-01: mask dangerous /proc write targets with /dev/null ──────────────────
# /proc is mounted read-only, but bind-mounting /dev/null over the most
# dangerous entries provides a second layer of defence in case of a kernel
# regression that re-enables writes.
for target in \
    /proc/sysrq-trigger \
    /proc/sys/kernel/core_pattern \
    /proc/sys/kernel/modprobe \
    /proc/sys/fs/binfmt_misc \
    /proc/kcore \
    /proc/kmem \
    /proc/mem; do
  [ -e "\$target" ] && mount --bind /dev/null "\$target" 2>/dev/null || true
done

# ── loopback ──────────────────────────────────────────────────────────────────
# Inside a fresh user+net namespace the process has CAP_NET_ADMIN scoped to
# that namespace, so this is safe and does not affect host networking.
ip link set lo up 2>/dev/null || \
  ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null || \
  true   # best-effort; some kernels auto-raise lo on ns creation

# ── HTTP server on loopback only ──────────────────────────────────────────────
# Serves the DITA project tree at http://127.0.0.1:${HTTP_PORT}/
# The --bind flag ensures it never listens on any external interface.
# Killed automatically when the jail exits (SIGTERM to the process group).
python3 -m http.server ${HTTP_PORT} \
  --bind 127.0.0.1 \
  --directory "${DITA_PROJECT}" \
  >/dev/null 2>&1 &

# Give the server a moment to be ready before the main process starts.
sleep 0.3

exec "\$@"
INNER_EOF
chmod 500 "$INNER_SCRIPT"

# ── assemble bind-mount flags ─────────────────────────────────────────────────
# Helper: emit the flag only when the source path exists on the host.
bind_ro() {
  local src="$1" dst="${2:-$1}"
  [[ -e "$src" ]] && printf '%s\0' "--bindmount_ro=${src}:${dst}"
}

# Build an array from NUL-delimited output (safe for paths with spaces).
mapfile -d '' BIND_FLAGS < <(
  # The ONLY host data the jail processes may read.
  printf '%s\0' "--bindmount_ro=${DITA_PROJECT}:${DITA_PROJECT}"

  # System binaries and libraries — read-only.
  # /sbin is intentionally excluded (E-09): not needed for DITA processing.
  bind_ro /usr
  bind_ro /bin
  bind_ro /lib
  bind_ro /lib64
  bind_ro /lib32
  bind_ro /libx32

  # Dynamic linker cache — needed by glibc and JVM.
  bind_ro /etc/ld.so.cache
  bind_ro /etc/ld.so.conf
  bind_ro /etc/ld.so.conf.d

  # Timezone data — needed by Java and logging frameworks.
  bind_ro /etc/localtime
  bind_ro /usr/share/zoneinfo

  # JVM TLS — only the system trust store, not the full SSL directory (E-16).
  bind_ro /etc/ssl/certs/java   /etc/ssl/certs/java

  # Inner wrapper.
  printf '%s\0' "--bindmount_ro=${INNER_SCRIPT}:/run/inner.sh"

  # Synthetic /etc files (E-19): passwd, group, resolv.conf from $ETC_DIR.
  printf '%s\0' "--bindmount_ro=${ETC_DIR}/passwd:/etc/passwd"
  printf '%s\0' "--bindmount_ro=${ETC_DIR}/group:/etc/group"
  printf '%s\0' "--bindmount_ro=${ETC_DIR}/resolv.conf:/etc/resolv.conf"
)

# ── capability drop list (E-03, E-04) ────────────────────────────────────────
# We drop every capability that has no legitimate use in a DITA build.
# Remaining caps (e.g. CAP_NET_ADMIN, CAP_SYS_ADMIN) are scoped to the jail's
# own namespaces via --clone_newuser and cannot affect the host.
CAP_DROPS=(
  --cap DROP:CAP_CHOWN
  --cap DROP:CAP_DAC_OVERRIDE
  --cap DROP:CAP_DAC_READ_SEARCH
  --cap DROP:CAP_FOWNER
  --cap DROP:CAP_FSETID
  --cap DROP:CAP_KILL
  --cap DROP:CAP_SETGID
  --cap DROP:CAP_SETUID
  --cap DROP:CAP_SETFCAP
  --cap DROP:CAP_SETPCAP
  --cap DROP:CAP_LINUX_IMMUTABLE
  --cap DROP:CAP_NET_BIND_SERVICE
  --cap DROP:CAP_NET_BROADCAST
  --cap DROP:CAP_NET_RAW
  --cap DROP:CAP_IPC_LOCK
  --cap DROP:CAP_IPC_OWNER
  --cap DROP:CAP_SYS_MODULE
  --cap DROP:CAP_SYS_RAWIO
  --cap DROP:CAP_SYS_CHROOT
  --cap DROP:CAP_SYS_PTRACE
  --cap DROP:CAP_SYS_PACCT
  --cap DROP:CAP_SYS_BOOT
  --cap DROP:CAP_SYS_NICE
  --cap DROP:CAP_SYS_RESOURCE
  --cap DROP:CAP_SYS_TIME
  --cap DROP:CAP_SYS_TTY_CONFIG
  --cap DROP:CAP_MKNOD
  --cap DROP:CAP_LEASE
  --cap DROP:CAP_AUDIT_WRITE
  --cap DROP:CAP_AUDIT_CONTROL
  --cap DROP:CAP_AUDIT_READ
  --cap DROP:CAP_WAKE_ALARM
  --cap DROP:CAP_BLOCK_SUSPEND
  --cap DROP:CAP_SYSLOG
  --cap DROP:CAP_PERFMON
  --cap DROP:CAP_BPF
  --cap DROP:CAP_CHECKPOINT_RESTORE
)

# ── execute ───────────────────────────────────────────────────────────────────
# Execution order:
#   prlimit  — AS + nproc + cpu-time + fsize rlimits for the whole subtree
#   taskset  — pin to a single CPU core
#   nsjail   — namespaces, chroot, seccomp, capability drops, bind mounts
#   inner.sh — /tmp resize, /proc masking, loopback, http.server, exec CMD

exec prlimit \
  --as="${MEM_LIMIT_BYTES}" \
  --nproc=256:256 \
  --cpu=3600:3600 \
  --fsize="${FSIZE_BYTES}" \
  --nofile=1024:1024 \
  taskset --cpu-list "${CPU_CORE}" \
  nsjail \
    \
    `# ── execution mode ──────────────────────────────────────────────────` \
    --mode o \
    --log_fd 2 \
    --time_limit "${TIME_LIMIT}" \
    \
    `# ── namespaces ───────────────────────────────────────────────────────` \
    --clone_newuser \
    --clone_newnet \
    --clone_newpid \
    --clone_newipc \
    --clone_newuts \
    \
    `# ── filesystem ───────────────────────────────────────────────────────` \
    --chroot "${ROOTFS}" \
    "${BIND_FLAGS[@]}" \
    --tmpfsmount /tmp \
    --tmpfsmount /dev \
    --proc_ro \
    --cwd "${DITA_PROJECT}" \
    \
    `# ── seccomp (E-02) ───────────────────────────────────────────────────` \
    --seccomp_string "$(cat "${SECCOMP_POLICY}")" \
    \
    `# ── capability drops (E-03, E-04) ───────────────────────────────────` \
    "${CAP_DROPS[@]}" \
    \
    `# ── inner entrypoint ─────────────────────────────────────────────────` \
    -- /bin/sh /run/inner.sh "$@"
