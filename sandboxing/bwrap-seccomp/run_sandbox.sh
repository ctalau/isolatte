#!/usr/bin/env bash
#
# Hardened hermetic bubblewrap sandbox
#
# Hardening layers:
#   1. User namespace  --unshare-user-try --uid 65534 --gid 65534
#      → runs as uid/gid 65534 (nobody); all caps zeroed; SUID ignored
#   2. Seccomp-BPF     --add-seccomp-fd
#      → blocks ptrace, process_vm_*, perf_event_open, kexec, bpf,
#        userfaultfd, mount/pivot/chroot, keyctl, iopl/ioperm,
#        open_by_handle_at, unshare/setns, fanotify, kcmp
#      → blocks socket(AF_INET/AF_INET6/AF_NETLINK/AF_PACKET) as net-ns
#        substitute (--unshare-net blocked by Docker host kernel)
#   3. FD cleanup      all inherited FDs above stderr closed before exec;
#                      bwrap stdout/stderr redirected to /dev/null so
#                      the sandbox sees /dev/null for fd1/fd2, not host paths
#   4. Namespace isolation: IPC, PID, UTS unshared
#   5. Minimal read-only filesystem (/home /root /etc /var /run /sys hidden)
#   6. Single writable path: /output bound from ./output/
#   7. --cap-drop ALL + --clearenv + --new-session + --die-with-parent
#
# Residual risks (documented below the run):
#   - net-ns sharing (Docker constraint), mitigated by seccomp inet block
#   - bwrap internal pipes visible inside sandbox (unavoidable, harmless)
#   - no --disable-userns (requires strict --unshare-user), mitigated by
#     seccomp blocking unshare/setns
#   - kernel CVE exposure (seccomp reduces, not eliminates, attack surface)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
FILTER_FILE="/tmp/sandbox_seccomp_$$.bpf"

cleanup() { rm -f "$FILTER_FILE"; }
trap cleanup EXIT

mkdir -p "$OUTPUT_DIR"

# ── 1. Compile seccomp generator if binary is missing ─────────────────
if [ ! -x "${SCRIPT_DIR}/gen_seccomp" ]; then
    echo "[*] Compiling seccomp filter generator..."
    gcc -O2 -o "${SCRIPT_DIR}/gen_seccomp" \
        "${SCRIPT_DIR}/gen_seccomp.c" -lseccomp
fi

# ── 2. Generate BPF filter ─────────────────────────────────────────────
"${SCRIPT_DIR}/gen_seccomp" "$FILTER_FILE"
echo "[*] Seccomp BPF filter generated ($(wc -c < "$FILTER_FILE") bytes)"

# ── 3. Open filter as a dedicated file descriptor ─────────────────────
exec {SECCOMP_FD}<"$FILTER_FILE"

# ── 4. Close all inherited FDs above stderr (except SECCOMP_FD) ───────
#    Prevents sandbox from writing to host files via inherited descriptors.
for fd in $(ls /proc/self/fd 2>/dev/null | sort -n); do
    if [ "$fd" -gt 2 ] && [ "$fd" -ne "$SECCOMP_FD" ]; then
        eval "exec ${fd}>&-" 2>/dev/null || true
    fi
done
echo "[*] Inherited FDs above stderr closed (seccomp_fd=$SECCOMP_FD kept)"
echo ""
echo "=== Launching hardened bubblewrap sandbox ==="

# ── 5. Run bwrap with stdout/stderr redirected to /dev/null ───────────
#    This ensures the sandbox sees fd1=/dev/null and fd2=/dev/null,
#    not whatever host-file paths the parent process had them pointed at.
#    Output is captured exclusively via the /output bind mount.
bwrap \
    --unshare-user-try \
    --uid  65534 \
    --gid  65534 \
    --unshare-ipc \
    --unshare-pid \
    --unshare-uts \
    --ro-bind /usr          /usr          \
    --ro-bind /lib          /lib          \
    --ro-bind /lib64        /lib64        \
    --ro-bind /opt/node22   /opt/node22   \
    --ro-bind "${SCRIPT_DIR}/print_date.js" /app/print_date.js \
    --bind    "$OUTPUT_DIR" /output        \
    --proc    /proc                        \
    --dev     /dev                         \
    --tmpfs   /tmp                         \
    --new-session                          \
    --die-with-parent                      \
    --clearenv                             \
    --setenv  PATH /opt/node22/bin         \
    --setenv  HOME /tmp                    \
    --cap-drop ALL                         \
    --add-seccomp-fd "$SECCOMP_FD"         \
    -- /opt/node22/bin/node /app/print_date.js \
    >/dev/null 2>/dev/null

echo ""
echo "=== Output written by sandboxed process ==="
cat "$OUTPUT_DIR/date.txt"
