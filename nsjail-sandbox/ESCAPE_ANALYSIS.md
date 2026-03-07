# Sandbox Escape Analysis — `sandbox_dita.sh` (v1)

Audited: `sandbox_dita.sh` + `nsjail.cfg` (initial commit `2a9a055`).
Each finding lists the relevant line(s), an exploit sketch, and what the
hardened version does to close it.

---

## Critical

### E-01 — `/proc` mounted read-write (`--proc_rw`)
**File:** `sandbox_dita.sh:213`
**Risk:** The jailed process can write to `/proc/sysrq-trigger` (instant
reboot/crash), `/proc/sys/kernel/core_pattern` (execute arbitrary binary as
root on next crash), `/proc/sys/fs/binfmt_misc/register` (register a new
binary interpreter executed with elevated privilege), and
`/proc/self/oom_score_adj` (prevent OOM killer from ever targeting this
process).
**Fix:** `--proc_ro`; additionally mask each dangerous `procfs` entry by
bind-mounting `/dev/null` over it inside the inner wrapper.

---

### E-02 — No seccomp filter
**File:** neither file has seccomp configuration.
**Risk:** Unrestricted syscall access allows:
- `ptrace` — attach to any child and inspect/overwrite its memory.
- `process_vm_readv` / `process_vm_writev` — read/write peer process memory
  without `ptrace`.
- `mount` / `pivot_root` / `move_mount` — remount read-only bind mounts as
  writable; pivot out of the chroot.
- `unshare` / `setns` — create new nested namespaces to bypass mount or
  network restrictions.
- `bpf(BPF_PROG_LOAD)` — load an eBPF program with kernel-level visibility.
- `mknod` / `mknodat` — create device nodes (see E-04).
- `kexec_load` — replace the running kernel.
- `open_by_handle_at` — look up arbitrary inodes by handle, bypassing mount
  restrictions.

**Fix:** `seccomp.policy` (kafel deny-list loaded via `--seccomp_string`).

---

### E-03 — Selective capability drop leaves dangerous caps enabled
**File:** `sandbox_dita.sh:220–224`
Only five capabilities are dropped. Still present in the bounding set:

| Capability | Exploit |
|---|---|
| `CAP_SYS_CHROOT` | Call `chroot()` a second time to escape the outer chroot |
| `CAP_DAC_OVERRIDE` | Bypass read/write permission checks on any file |
| `CAP_DAC_READ_SEARCH` | `open()` any file; `stat()` any directory |
| `CAP_SETUID` / `CAP_SETGID` | Re-become UID 0 inside the jail |
| `CAP_SETFCAP` | Stamp file capabilities on binaries under `/tmp` |
| `CAP_CHOWN` | Take ownership of any file |
| `CAP_NET_RAW` | Raw sockets; bypass loopback-only network restriction |
| `CAP_IPC_LOCK` | Pin unlimited memory; defeats the AS limit |
| `CAP_MKNOD` | Create device nodes (see E-04) |
| `CAP_SYSLOG` | Read the host kernel ring buffer |
| `CAP_AUDIT_*` | Manipulate audit subsystem |

**Fix:** Drop the full dangerous set explicitly; rely on user namespace for
capability scoping so that remaining caps apply only within the jail's own
namespaces.

---

### E-04 — Writable `/dev` tmpfs with `mknod` ability
**File:** `sandbox_dita.sh:212`
**Risk:** With `CAP_MKNOD` (not dropped) and no seccomp filter blocking
`mknod(2)`, the process can create `/dev/mem`, `/dev/kmem`, `/dev/sda`, etc.
and access host hardware or kernel memory directly.
**Fix:** Drop `CAP_MKNOD`; add `mknod`/`mknodat` to seccomp deny-list; pass
`nodev,nosuid` mount flags on `/dev`.

---

## High

### E-05 — `/tmp` tmpfs has no size limit
**File:** `sandbox_dita.sh:211`
**Risk:** The `--as` rlimit caps virtual address space, but `tmpfs` writes go
to page cache, not the process's address space. A process can write hundreds of
gigabytes to `/tmp` via `write(2)` and exhaust host RAM/swap, causing a
system-wide OOM.
**Fix:** Remount `/tmp` with `size=128m` inside the inner wrapper (feasible
because the user namespace grants `CAP_SYS_ADMIN` within the mount namespace).

---

### E-06 — No `--nproc` rlimit → fork bombs
**File:** `sandbox_dita.sh:197–199`
**Risk:** `prlimit` only sets `--as` and `--nofile`. The process can `fork()`
or `clone()` arbitrarily, exhausting kernel PID space and bringing the host to
a halt.
**Fix:** `prlimit --nproc=256:256`.

---

### E-07 — No CPU-time rlimit
**File:** `sandbox_dita.sh:197–199`
**Risk:** `taskset` pins to one core but does not limit CPU seconds. An
infinite loop burns one entire core indefinitely.
**Fix:** `prlimit --cpu=3600:3600` (1 CPU-hour hard cap).

---

### E-08 — No file-size rlimit
**File:** `sandbox_dita.sh:197–199`
**Risk:** A process can write a single file consuming all free space on the
`tmpfs` (or, if the chroot escapes, on the host filesystem).
**Fix:** `prlimit --fsize=$((512*1024*1024))` (512 MiB max file).

---

### E-09 — `/sbin` bind-mounted (exposes `iptables`, `insmod`, `modprobe`, …)
**File:** `sandbox_dita.sh:168`, `nsjail.cfg:82`
**Risk:** Even read-only, mounting `/sbin` gives the process access to kernel
module helpers. If any `suid` binary exists under `/sbin` and caps are not
fully dropped, it becomes an elevation vector.
**Fix:** Do not mount `/sbin`; it is not required for DITA processing.

---

### E-10 — Inner wrapper script stored in world-readable `/tmp`
**File:** `sandbox_dita.sh:119`
**Risk:** Another process running as the same UID could race between `mktemp`
and the `chmod +x` call, replacing the script with a payload. Even without a
race, the script content is visible to any process on the host.
**Fix:** Create the script inside a `chmod 700` subdirectory owned by the
invoking user; set the file itself to mode `500` immediately after creation.

---

### E-11 — Rootfs skeleton created in world-accessible `/tmp`
**File:** `sandbox_dita.sh:95`
**Risk:** `mktemp -d` creates the directory with mode `700`, but a concurrent
`ls /tmp` scan reveals it. More critically, files subsequently created under it
(via `mkdir -p "$ROOTFS$DITA_PROJECT"`) are visible from the host.
**Fix:** `chmod 700 "$ROOTFS"` immediately after `mktemp -d` (it is already
700 by default, but document and enforce it explicitly).

---

## Medium

### E-12 — No IPC namespace in shell script
**File:** `sandbox_dita.sh` — `--clone_newipc` absent from the nsjail invocation.
**Risk:** The jailed process shares System V shared memory segments, message
queues, and semaphores with the host. Attaching to a host service's SHM
segment is possible if the IDs are guessable.
**Fix:** Add `--clone_newipc`.

---

### E-13 — No user namespace (`--clone_newuser`)
**File:** `sandbox_dita.sh` — flag absent.
**Risk:** Without a user namespace, the jailed process runs with the real
UID/GID of the caller. If the caller is root, the jailed process is also root
on the host. Capability drops apply in principle but have no namespace
boundary to back them up.
**Fix:** Add `--clone_newuser`; capabilities are then scoped to the jail's
namespaces and cannot affect the host even if a cap-drop is missed.

---

### E-14 — DITA_PROJECT path not validated for symlinks or sensitive targets
**File:** `sandbox_dita.sh:74`
**Risk:** `[[ -d "$DITA_PROJECT" ]]` accepts `/etc`, `/root`, `/proc/1`,
or any path containing symlinks that traverse outside the intended tree.
The bind mount exposes whatever the symlink resolves to.
**Fix:** Resolve the path with `realpath --canonicalize-existing` and reject
paths outside a configurable allow-root (e.g. `/home`, `/data`).

---

### E-15 — `CAP_NET_ADMIN` dropped but loopback setup still attempted in wrapper
**File:** `sandbox_dita.sh:128–130`
**Risk:** With the cap dropped, `ip link set lo up` silently fails, leaving
loopback down. The HTTP server then cannot bind, and the sandboxed process
operates without its expected data source — a correctness and reliability
failure that could mask further issues.
**Fix:** Rely on user-namespace-scoped `CAP_NET_ADMIN` (present because the
inner process IS UID 0 within its own user+net namespace) rather than dropping
it at the nsjail bounding-set level. The cap is harmless within the isolated
net namespace.

---

### E-16 — Entire `/etc/ssl/certs` tree unnecessarily mounted
**File:** `sandbox_dita.sh:185`, `nsjail.cfg:93`
**Risk:** With loopback-only networking, TLS to external hosts is impossible.
Mounting the CA bundle increases attack surface and leaks host PKI
configuration.
**Fix:** Remove the mount; note it in comments for re-enabling if TLS-over-lo
is ever needed.

---

### E-17 — `rlimit_as` and `rlimit_nofile` commented out in `nsjail.cfg`
**File:** `nsjail.cfg:107–108`
**Risk:** If the config file is used directly (e.g., `nsjail --config
nsjail.cfg`) without the external `prlimit` wrapper, resource limits are not
enforced at all.
**Fix:** Uncomment and set these in the config as a belt-and-suspenders layer;
keep the external `prlimit` call too.

---

## Low / Informational

### E-18 — `--time_limit 0` (no wall-clock timeout)
**File:** `sandbox_dita.sh:206`
**Risk:** A stalled or infinite-loop process runs forever. The CPU-time rlimit
(once added) bounds CPU usage but not wall time (e.g., a process blocking on
`read()` forever).
**Fix:** Set `--time_limit 86400` (24 h) as a safety backstop.

---

### E-19 — `/etc/passwd`, `/etc/group`, `/etc/resolv.conf` expose host metadata
**File:** `sandbox_dita.sh:181–183`
**Risk:** Read-only, so no write exploit. But the process learns real usernames,
UIDs, group memberships, and DNS server addresses of the host.
**Fix:** Supply minimal synthetic versions: a two-line `passwd` with only
`nobody` and `root`; an empty `resolv.conf` (DNS is unreachable anyway).

---

### E-20 — Python `http.server` runs without explicit `--directory` canonicalization
**File:** `sandbox_dita.sh:136–138`
**Risk:** If `DITA_PROJECT` resolves to a directory with symlinks pointing
outside it, `http.server` will follow them and serve files outside the
intended tree.
**Fix:** Covered by E-14 (canonicalize DITA_PROJECT before use).

---

## Summary table

| ID | Severity | Category | Closed by |
|----|----------|----------|-----------|
| E-01 | Critical | Filesystem | `--proc_ro` + mask dangerous procfs entries |
| E-02 | Critical | Syscall | `seccomp.policy` |
| E-03 | Critical | Privilege | Full cap drop list |
| E-04 | Critical | Device | `CAP_MKNOD` drop + seccomp `mknod` |
| E-05 | High | Resource | `mount -o remount,size=128m /tmp` in inner script |
| E-06 | High | Resource | `prlimit --nproc=256:256` |
| E-07 | High | Resource | `prlimit --cpu=3600:3600` |
| E-08 | High | Resource | `prlimit --fsize=...` |
| E-09 | High | Filesystem | Remove `/sbin` bind mount |
| E-10 | High | TOCTOU | Secure temp dir + mode 500 script |
| E-11 | High | Filesystem | Enforce mode 700 on ROOTFS |
| E-12 | Medium | IPC | `--clone_newipc` |
| E-13 | Medium | Privilege | `--clone_newuser` |
| E-14 | Medium | Filesystem | `realpath` + path allow-root check |
| E-15 | Medium | Network | User-namespace-scoped net admin |
| E-16 | Medium | Filesystem | Remove `/etc/ssl/certs` mount |
| E-17 | Medium | Config | Uncomment rlimits in `nsjail.cfg` |
| E-18 | Low | Resource | `--time_limit 86400` |
| E-19 | Low | Info leak | Synthetic `/etc/passwd` + `/etc/group` |
| E-20 | Low | Filesystem | Covered by E-14 |
