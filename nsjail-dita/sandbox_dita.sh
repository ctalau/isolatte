#!/usr/bin/env bash
# sandbox_dita.sh — Run a process inside an nsjail sandbox, isolated to the
# DITA project directory, with CPU/memory limits and loopback-only networking.
#
# Isolation layers:
#   nsjail  — mount + network + pid + uts namespaces; chroot to a minimal rootfs
#             that exposes only the DITA project tree (bind-mounted read-only).
#   prlimit — 1 GiB virtual-address-space cap; tight file-descriptor limit.
#   taskset — pin the whole process tree to a single CPU core.
#   http.server — python3 -m http.server runs inside the jail's network
#                 namespace (loopback only), so the sandboxed process can fetch
#                 DITA content over HTTP without any external network access.
#
# Usage:
#   DITA_PROJECT=/path/to/dita-ot ./sandbox_dita.sh -- dita-ot.sh build
#   ./sandbox_dita.sh --dita-project /data/myproject -- java -jar dita-ot.jar
#
# Prerequisites:
#   sudo apt-get install nsjail util-linux  # for nsjail + taskset + prlimit
#
# Environment variables (all optional):
#   DITA_PROJECT      Path to the DITA project directory (default: /opt/dita-ot)
#   HTTP_SERVER_PORT  Port the internal HTTP server listens on  (default: 8000)
#   CPU_CORE          CPU core index to pin execution to        (default: 0)
#   MEM_LIMIT_MiB     Address-space limit in MiB                (default: 1024)
#   NSJAIL_LOG_FD     File descriptor for nsjail logs           (default: 2/stderr)

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
DITA_PROJECT="${DITA_PROJECT:-/opt/dita-ot}"
HTTP_SERVER_PORT="${HTTP_SERVER_PORT:-8000}"
CPU_CORE="${CPU_CORE:-0}"
MEM_LIMIT_MiB="${MEM_LIMIT_MiB:-1024}"
NSJAIL_LOG_FD="${NSJAIL_LOG_FD:-2}"

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[sandbox] $*" >&2; }

usage() {
  cat >&2 <<'EOF'
Usage: sandbox_dita.sh [OPTIONS] -- COMMAND [ARGS...]

Options:
  --dita-project PATH   DITA project root (env: DITA_PROJECT, default /opt/dita-ot)
  --http-port    PORT   Internal HTTP server port (env: HTTP_SERVER_PORT, default 8000)
  --cpu-core     N      CPU core to pin to (env: CPU_CORE, default 0)
  --mem-limit    MiB    Address-space cap in MiB (env: MEM_LIMIT_MiB, default 1024)
  -h, --help            Show this message

Inside the jail the DITA project is mounted at the same path as on the host
(read-only) and also served at http://127.0.0.1:PORT/.
EOF
  exit 1
}

# ── argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dita-project) DITA_PROJECT="$2";    shift 2 ;;
    --http-port)    HTTP_SERVER_PORT="$2"; shift 2 ;;
    --cpu-core)     CPU_CORE="$2";        shift 2 ;;
    --mem-limit)    MEM_LIMIT_MiB="$2";   shift 2 ;;
    -h|--help)      usage ;;
    --)             shift; break ;;
    *) die "Unknown option: $1  (run with --help for usage)" ;;
  esac
done

[[ $# -gt 0 ]] || die "No command specified after '--' (run with --help for usage)"

# ── validation ────────────────────────────────────────────────────────────────
command -v nsjail  >/dev/null 2>&1 || die "nsjail not found (install: sudo apt-get install nsjail)"
command -v prlimit >/dev/null 2>&1 || die "prlimit not found (install: sudo apt-get install util-linux)"
command -v taskset >/dev/null 2>&1 || die "taskset not found (install: sudo apt-get install util-linux)"
command -v python3 >/dev/null 2>&1 || die "python3 not found (required for http.server)"

[[ "$MEM_LIMIT_MiB"     =~ ^[0-9]+$   ]] || die "--mem-limit must be a positive integer"
[[ "$CPU_CORE"          =~ ^[0-9]+$   ]] || die "--cpu-core must be a non-negative integer"
[[ "$HTTP_SERVER_PORT"  =~ ^[0-9]+$   ]] || die "--http-port must be a positive integer"

# Resolve to an absolute, normalised path to prevent path-traversal and
# shell-metacharacter injection into the inner script template.
DITA_PROJECT=$(realpath -m "$DITA_PROJECT")
[[ "$DITA_PROJECT" == /* ]] || die "DITA_PROJECT must resolve to an absolute path"
[[ -d "$DITA_PROJECT"    ]] || die "DITA project directory not found: $DITA_PROJECT"

# Capture the calling user's UID/GID for the user-namespace mapping below.
HOST_UID=$(id -u)
HOST_GID=$(id -g)

MEM_LIMIT_BYTES=$(( MEM_LIMIT_MiB * 1024 * 1024 ))

info "DITA project : $DITA_PROJECT"
info "CPU core     : $CPU_CORE"
info "Memory limit : ${MEM_LIMIT_MiB} MiB (${MEM_LIMIT_BYTES} bytes)"
info "HTTP port    : $HTTP_SERVER_PORT"
info "Command      : $*"

# ── build minimal rootfs ──────────────────────────────────────────────────────
# nsjail's --chroot requires a directory that will become / inside the jail.
# We create a skeleton here; the real content comes from bind mounts below.
ROOTFS=$(mktemp -d /tmp/dita-sandbox-rootfs-XXXXXX)

cleanup() {
  # Unmount anything that may have been mounted by the OS into ROOTFS.
  # nsjail cleans up its own mounts; this covers edge cases.
  mountpoint -q "$ROOTFS/proc" 2>/dev/null && umount -l "$ROOTFS/proc" || true
  rm -rf "$ROOTFS"
  rm -f  "$INNER_SCRIPT"
}
trap cleanup EXIT

# Skeleton directories required by standard Linux tools inside the jail.
mkdir -p "$ROOTFS"/{proc,sys,dev,tmp,run,etc,home}

# Recreate the host directory structure for the DITA project mount point.
# (nsjail bind mounts need the target path to exist inside the rootfs.)
mkdir -p "$ROOTFS$DITA_PROJECT"

# ── inner wrapper script ──────────────────────────────────────────────────────
# This script runs *inside* the jail as PID 1 of the sandboxed subtree.
# It:
#   1. Brings up the loopback interface (new net namespace starts with lo down).
#   2. Starts python3 -m http.server on 127.0.0.1 only.
#   3. Execs the user-supplied command.
INNER_SCRIPT=$(mktemp /tmp/dita-sandbox-inner-XXXXXX.sh)

# Use a QUOTED heredoc delimiter ('INNER_EOF') so the outer shell performs NO
# variable expansion while writing the template.  HTTP_SERVER_PORT and
# DITA_PROJECT reach the inner script as environment variables set via
# nsjail --env (see below), avoiding command-injection through their values.
cat > "$INNER_SCRIPT" <<'INNER_EOF'
#!/bin/sh
set -e

# ── loopback ──────────────────────────────────────────────────────────────────
# nsjail creates the new network namespace but does not automatically bring lo
# up.  We need it for the HTTP server to bind to 127.0.0.1.
ip link set lo up 2>/dev/null || \
  ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null || \
  true  # best-effort; some kernels auto-bring lo up on namespace creation

# ── HTTP server ───────────────────────────────────────────────────────────────
# Serve the DITA project tree at http://127.0.0.1:${HTTP_SERVER_PORT}/
# --bind 127.0.0.1 ensures it never binds to any external interface.
# Running in the background; killed automatically when the jail exits.
# HTTP_SERVER_PORT and DITA_PROJECT are injected as env vars by nsjail --env.
python3 -m http.server "${HTTP_SERVER_PORT}" \
  --bind 127.0.0.1 \
  --directory "${DITA_PROJECT}" \
  >/dev/null 2>&1 &

# Give the server a moment to become ready before the main process starts.
sleep 0.3

# ── exec user command ─────────────────────────────────────────────────────────
exec "$@"
INNER_EOF

chmod +x "$INNER_SCRIPT"

# ── assemble the nsjail bind-mount flags ──────────────────────────────────────
# We expose the minimum required to run python3/sh plus the DITA project.
# All system directories are read-only.  Only /tmp is writable.

bind_ro() {
  # Emits "--bindmount_ro SRC:DST" only when SRC exists on the host.
  local src="$1" dst="${2:-$1}"
  [[ -e "$src" ]] && echo "--bindmount_ro ${src}:${dst}" || true
}

BIND_FLAGS=(
  # DITA project — the only host data the jail is meant to access (read-only).
  "--bindmount_ro ${DITA_PROJECT}:${DITA_PROJECT}"

  # Minimal system tree required to run a POSIX shell and python3.
  $(bind_ro /usr)
  $(bind_ro /bin)
  $(bind_ro /sbin)
  $(bind_ro /lib)
  $(bind_ro /lib64)
  $(bind_ro /lib32)
  $(bind_ro /libx32)

  # Wrapper script — injected at a fixed path inside the jail.
  "--bindmount_ro ${INNER_SCRIPT}:/run/sandbox-inner.sh"

  # Minimal /etc entries needed by glibc and python3.
  $(bind_ro /etc/ld.so.cache)
  $(bind_ro /etc/ld.so.conf)
  $(bind_ro /etc/ld.so.conf.d)
  $(bind_ro /etc/resolv.conf)   # kept but irrelevant with --clone_newnet
  $(bind_ro /etc/nsswitch.conf)
  $(bind_ro /etc/passwd)
  $(bind_ro /etc/group)
  $(bind_ro /etc/localtime)
  $(bind_ro /etc/ssl/certs)     # CA bundle, in case TLS is needed over lo
)

# ── seccomp-BPF policy ────────────────────────────────────────────────────────
# Block syscalls that are unnecessary for DITA-OT and would allow a confined
# process to bypass the namespace or filesystem isolation layers.
# Applied on top of the capability drops and user-namespace isolation for
# defense in depth.
SECCOMP_POLICY='POLICY dita_sandbox {
  KILL_PROCESS {
    unshare,
    mount, umount2, pivot_root,
    mknod, mknodat,
    perf_event_open,
    bpf,
    process_vm_writev, process_vm_readv,
    swapon, swapoff,
    kexec_load, kexec_file_load,
    reboot
  }
}
USE dita_sandbox DEFAULT ALLOW'

# ── run ───────────────────────────────────────────────────────────────────────
# Execution order (outermost → innermost):
#
#   prlimit   — sets AS (virtual memory) and NOFILE rlimits for the subtree
#   taskset   — pins all threads/children to the specified CPU core
#   nsjail    — creates isolated namespaces and execs the inner script
#   sh        — inner wrapper (lo up + http.server + exec user command)
#   COMMAND   — the user-supplied workload (e.g. dita-ot build)

exec prlimit \
  --as="${MEM_LIMIT_BYTES}" \
  --nofile=1024:1024 \
  taskset --cpu-list "${CPU_CORE}" \
  nsjail \
    \
    `# ── execution mode ──────────────────────────────────────────────────` \
    --mode o \
    --log_fd "${NSJAIL_LOG_FD}" \
    --time_limit 600 \
    \
    `# ── filesystem isolation ─────────────────────────────────────────────` \
    --chroot "${ROOTFS}" \
    "${BIND_FLAGS[@]}" \
    --tmpfsmount /tmp \
    --tmpfsmount /dev \
    --cwd "${DITA_PROJECT}" \
    \
    `# ── network isolation ────────────────────────────────────────────────` \
    --clone_newnet \
    \
    `# ── user and ID isolation ─────────────────────────────────────────────` \
    `# Creates a user namespace so all capabilities are scoped to the jail.  ` \
    `# Inside UID/GID 1000 maps to the calling user's UID/GID on the host.   ` \
    `# A process that escapes the chroot is still an unprivileged host user.  ` \
    --clone_newuser \
    --uidmap "1000:${HOST_UID}:1" \
    --gidmap "1000:${HOST_GID}:1" \
    \
    `# ── capability restrictions inside the jail ──────────────────────────` \
    `# Defense-in-depth: drop all capabilities not needed by DITA-OT.        ` \
    `# CAP_NET_ADMIN is retained because the inner script brings up loopback; ` \
    `# with --clone_newuser it is scoped to the jail's network namespace only.` \
    --cap DROP:CAP_CHOWN \
    --cap DROP:CAP_DAC_OVERRIDE \
    --cap DROP:CAP_DAC_READ_SEARCH \
    --cap DROP:CAP_FOWNER \
    --cap DROP:CAP_FSETID \
    --cap DROP:CAP_KILL \
    --cap DROP:CAP_SETGID \
    --cap DROP:CAP_SETUID \
    --cap DROP:CAP_SETPCAP \
    --cap DROP:CAP_SETFCAP \
    --cap DROP:CAP_NET_BIND_SERVICE \
    --cap DROP:CAP_NET_RAW \
    --cap DROP:CAP_NET_BROADCAST \
    --cap DROP:CAP_SYS_ADMIN \
    --cap DROP:CAP_SYS_PTRACE \
    --cap DROP:CAP_SYS_MODULE \
    --cap DROP:CAP_SYS_RAWIO \
    --cap DROP:CAP_SYS_CHROOT \
    --cap DROP:CAP_SYS_RESOURCE \
    --cap DROP:CAP_SYS_BOOT \
    --cap DROP:CAP_SYS_NICE \
    --cap DROP:CAP_SYS_TIME \
    --cap DROP:CAP_MKNOD \
    --cap DROP:CAP_AUDIT_WRITE \
    --cap DROP:CAP_AUDIT_CONTROL \
    --cap DROP:CAP_AUDIT_READ \
    \
    `# ── seccomp-BPF syscall filter ────────────────────────────────────────` \
    --seccomp_string "${SECCOMP_POLICY}" \
    \
    `# ── environment variables ─────────────────────────────────────────────` \
    `# Pass validated values into the jail so the quoted inner script can use ` \
    `# them without any risk of outer-shell expansion or injection.           ` \
    --env "HTTP_SERVER_PORT=${HTTP_SERVER_PORT}" \
    --env "DITA_PROJECT=${DITA_PROJECT}" \
    \
    `# ── inner entrypoint ─────────────────────────────────────────────────` \
    -- /bin/sh /run/sandbox-inner.sh "$@"
