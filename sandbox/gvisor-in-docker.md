# gVisor inside a privileged Docker container on the dev-box

Runs a Node.js script inside a gVisor sandbox, which itself runs inside a
privileged Docker container on the dev-box (a VirtualBox VM).

```
dev-box  (VirtualBox VM, Linux 5.15)
  └── Docker privileged container  (Ubuntu 22.04)
        └── gVisor sandbox  (synthetic kernel 4.19.0-gvisor, systrap mode)
              └── Node.js process
```

## One-time setup

```bash
# 1. Start a privileged Ubuntu container
docker run -d --privileged --name gvisor-sandbox ubuntu:22.04 sleep infinity

# 2. Install gVisor (runsc) and Node.js inside it
docker exec gvisor-sandbox bash -c '
  apt-get update -qq
  apt-get install -y curl gnupg ca-certificates nodejs

  curl -fsSL https://gvisor.dev/archive.key \
    | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg

  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
    https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list

  apt-get update -qq
  apt-get install -y runsc
'
```

## Running a Node.js script under gVisor

```bash
docker exec gvisor-sandbox \
  runsc --network=none \
  do node -e "console.log('Hello from gVisor:', process.version)"
```

To run a script file, bind-mount it first or write it inside the container:

```bash
docker cp my-script.js gvisor-sandbox:/tmp/my-script.js
docker exec gvisor-sandbox \
  runsc --network=none \
  do node /tmp/my-script.js
```

Verify the process is actually running inside gVisor (should print `4.19.0-gvisor`):

```bash
docker exec gvisor-sandbox \
  runsc --network=none \
  do cat /proc/version
```

## Flags explained

| Flag | Why it is used |
|---|---|
| `--network=none` | Prevents the sandboxed process from making outbound connections or listening on ports. A meaningful hardening step for untrusted code; omit only if the guest genuinely needs network access. |

`systrap` is the default platform as of `release-20260601.0` and works inside a
privileged Docker container on VirtualBox without any extra flags. It intercepts
syscalls via seccomp-bpf rather than ptrace, so `CAP_SYS_PTRACE` is not required.

## Permissions granted to the Docker container

`--privileged` grants the container all of the following:

| What is granted | Effect |
|---|---|
| All Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, …) | The container process can do almost anything the host kernel allows, including mounting filesystems, loading kernel modules, and modifying network interfaces. |
| Unrestricted `/proc` and `/sys` | Read/write access to host kernel tunables and hardware interfaces. |
| All host devices (`/dev/*`) | Direct device access (block devices, `tun`, `fuse`, etc.). |
| Disabled seccomp filter | The default Docker seccomp profile (which blocks ~40 syscalls) is not applied. |
| Disabled AppArmor / SELinux profile | Mandatory access control policies are not enforced on the container. |

`CAP_SYS_ADMIN` is what the systrap platform needs: gVisor Sentry creates user,
mount, and pid namespaces and bind-mounts for the sandbox root.

## Security trade-offs

### The container itself is not isolated from the host

`--privileged` is equivalent to "no container boundary". A process that escapes
gVisor (or runs outside it) inside this container can:

- Mount the host filesystem.
- Modify host network configuration.
- Access raw block devices.
- Load or unload kernel modules.

This is acceptable only when the container itself is considered a trusted
execution environment — i.e. you control what runs in it.

### gVisor does add a meaningful isolation layer for the guest workload

Even though the container is privileged, any code executed via `runsc do` runs
inside gVisor's synthetic kernel. gVisor intercepts every syscall and re-implements
it in userspace, so the guest process never directly reaches the host kernel. This
limits the blast radius of a malicious or buggy Node.js script: it cannot escape
to the host kernel even if it exploits a Node.js or V8 vulnerability.

### systrap mode is faster than ptrace but still has no hardware boundary

| Mode | How it works | Overhead | Requires |
|---|---|---|---|
| `systrap` | gVisor intercepts syscalls via seccomp-bpf, re-implementing them in userspace (default) | ~1.5–3× slower than native for syscall-heavy workloads | `CAP_SYS_ADMIN` only |
| `ptrace` | gVisor traces the guest process with `ptrace`, intercepting every syscall in userspace | ~2–5× slower than native for syscall-heavy workloads | `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` |
| `KVM` | gVisor runs as a VMM using hardware virtualisation | Near-native | `/dev/kvm` (not available in VirtualBox without nested-virt) |

With systrap (and ptrace) mode, the Sentry and the guest process both run in ring 3
with no hardware boundary between them. KVM mode is substantially stronger because
hardware virtualisation enforces that boundary.

### `--network=none` prevents network-based attacks from the sandbox

With no network interface inside the gVisor sandbox the guest script cannot
make outbound connections or listen on ports. This is a meaningful hardening
step for running untrusted code.

---

## Analysis

### Can `--privileged` be replaced with narrower capabilities?

Yes. `--privileged` is a blunt instrument; the actual requirements of
`runsc` with the systrap platform are:

| Requirement | Why |
|---|---|
| `CAP_SYS_ADMIN` | Sentry creates user/mount/pid namespaces and bind-mounts for the sandbox root. |
| Seccomp: `unconfined` (or a custom profile) | Docker's default seccomp profile blocks several syscalls that runsc issues. |
| AppArmor/SELinux: `unconfined` | The default Docker AppArmor profile restricts operations that Sentry needs. |

`CAP_NET_ADMIN` is only required when networking is enabled; with `--network=none`
it is unnecessary. `CAP_SYS_PTRACE` is not needed by systrap. All other
capabilities granted by `--privileged` (device access, write access to
`/proc`/`/sys`, ability to load kernel modules) are not needed.

Minimal equivalent:

```bash
docker run -d \
  --cap-drop ALL \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --name gvisor-sandbox ubuntu:22.04 sleep infinity
```

This removes the most dangerous `--privileged` grants: raw device access,
host `/proc`/`/sys` writability, and the ability to load kernel modules. The
container can no longer trivially escape to the host even if gVisor is
bypassed.

---

### Does the Node process have access to the host filesystem?

**No — not by default.** There are two independent boundaries:

1. **Docker boundary:** `docker run` without a `-v` bind-mount does not expose
   the host filesystem to the container. The container has its own overlay
   filesystem.
2. **gVisor boundary:** `runsc do` mounts the container's own filesystem as the
   sandbox root. The Node process sees that filesystem through gVisor's
   synthetic VFS, not the host kernel.

With `--privileged`, the *container process* (e.g. the `runsc` binary itself)
can access host block devices like `/dev/sda` and could mount the host
filesystem manually — but code running *inside* `runsc do` cannot, because it
never reaches the host kernel directly.

**To expose a specific host directory to the Node process:**

```bash
# 1. Bind-mount the host directory into the Docker container
docker run -d --privileged \
  -v /host/path/to/data:/data \
  --name gvisor-sandbox ubuntu:22.04 sleep infinity

# 2. The path /data is now in the container filesystem, which runsc do exposes
#    to the sandbox automatically
docker exec gvisor-sandbox \
  runsc --network=none \
  do node -e "require('fs').readdirSync('/data').forEach(f => console.log(f))"
```

The bind-mount passes through two translation layers: Docker's overlay FS
exposes it to the container, and gVisor's VFS re-exposes it to the guest.
Write operations from Node go through gVisor → container overlay → host kernel,
so host-visible changes work but carry the performance overhead of both layers.

**To restrict the Node process to a specific folder only (confirmed working):**

`runsc do` exposes the entire container filesystem to the sandbox by default.
To restrict to a single folder, build a minimal rootfs containing only the Node
binary, its shared libraries, and the allowed data directory, then pass
`--root <rootfs>` to `runsc do`. The sandbox root becomes that directory; paths
outside it do not exist from the guest's perspective.

```bash
# 1. Build minimal rootfs inside the container (one-time)
docker exec gvisor-sandbox bash -c '
  mkdir -p /myroot/{bin,lib/x86_64-linux-gnu,lib64,proc,sys,dev,tmp,data}
  cp $(which node) /myroot/bin/
  ldd $(which node) | grep "=> /" | awk "{print \$3}" | \
    xargs -I{} cp {} /myroot/lib/x86_64-linux-gnu/
  cp /lib64/ld-linux-x86-64.so.2 /myroot/lib64/
'

# 2. Run with --root pointing at the minimal rootfs, --volume to inject the
#    allowed folder. Nothing outside /myroot is visible to Node.
docker exec gvisor-sandbox \
  runsc --network=none \
  do --root /myroot --volume /host/path/to/data:/data \
  node /data/script.js
```

Verified behaviour (tested on release-20260601.0 / Ubuntu 22.04):

| Access attempt from inside Node | Result |
|---|---|
| `fs.readFileSync('/data/hello.txt')` | ✅ succeeds |
| `fs.readFileSync('/secret.txt')` (exists in container but outside rootfs) | `ENOENT` |
| `fs.readFileSync('/../secret.txt')` (path traversal attempt) | `ENOENT` |
| `fs.readdirSync('/')` | returns only `bin, data, dev, lib, lib64, proc, sys, tmp` |

The `--volume SRC:DST` flag is the clean alternative to pre-mounting with
`mount --bind`; both produce the same isolation. gVisor's VFS enforces the
rootfs boundary independently of the Linux kernel's chroot — escaping via
`/../` is not possible because the Sentry re-implements path resolution
entirely in userspace and treats `/myroot` as the absolute root.

---

### How strong is systrap mode? Comparison with bubblewrap, Docker, and KVM

The four mechanisms differ on two axes: *whether syscalls are intercepted
before reaching the host kernel*, and *whether there is a hardware isolation
boundary*.

| Mechanism | Syscall path | Hardware boundary | Isolation model |
|---|---|---|---|
| **bubblewrap** | Guest → host kernel directly (filtered by seccomp-bpf) | None | Linux namespaces + seccomp filter |
| **Docker** (no gVisor) | Guest → host kernel directly (filtered by seccomp profile + AppArmor) | None | Linux namespaces + cgroups + seccomp/AppArmor |
| **gVisor systrap** | Guest → Sentry (userspace, seccomp-bpf intercept) → host kernel | None (both Sentry and guest are in ring 3) | Syscall re-implementation in userspace |
| **gVisor KVM** | Guest → Sentry (ring 0 inside VM) → KVM hypervisor → host kernel | Hardware VM boundary | Syscall re-implementation + hardware virtualisation |

**bubblewrap** is the weakest. Syscalls go directly to the host kernel; the
only protection is a seccomp-bpf allowlist. Any unfiltered kernel vulnerability
is exploitable. There is no syscall interposition layer, so a zero-day in
`write(2)` or `mmap(2)` is game over. bubblewrap is roughly Docker without the
tooling.

**Docker (default)** is marginally stronger than bubblewrap because it ships a
curated seccomp profile (blocks ~300 syscalls) and an AppArmor profile by
default. But the fundamental model is the same: syscalls reach the host kernel.
A kernel vulnerability reachable through the allowed syscall surface breaks out.

**gVisor systrap** adds a meaningful layer: syscalls from the guest process never
reach the host kernel. Sentry intercepts each one via seccomp-bpf, re-implements
it in userspace, and only issues the minimal set of host syscalls needed to
satisfy it. A kernel vulnerability in, say, `io_uring` or `keyctl` cannot be
triggered from inside the sandbox at all if Sentry does not implement those
syscalls. Compared to ptrace mode, systrap is faster and does not require
`CAP_SYS_PTRACE`, slightly reducing the attack surface.

However, systrap still has two structural weaknesses:

1. **No hardware boundary.** Sentry and the guest process both execute in ring 3.
   A bug in Sentry's syscall re-implementations or its seccomp-bpf dispatch is a
   potential escape vector.

2. **Large TCB.** The entire Sentry binary (hundreds of thousands of lines of Go)
   plus the host kernel's seccomp-bpf path form the trusted computing base.

**gVisor KVM** is substantially stronger. Sentry runs as the kernel of a
lightweight VM; KVM enforces a hardware ring boundary between it and the host.
Exploiting a bug in Sentry's syscall code gives the attacker control of the
Sentry VM, not the host. Escaping further requires a KVM hypervisor
vulnerability or a hardware side-channel (Spectre/Meltdown class). The attack
surface narrows dramatically: only the KVM interface is exposed to Sentry, not
the full host kernel syscall path.

**Practical ranking (weakest → strongest isolation for untrusted code):**

1. bubblewrap — namespaces + seccomp only, direct kernel access
2. Docker default — same model, slightly better seccomp/AppArmor defaults
3. **gVisor systrap** — syscall interposition via seccomp-bpf; no hardware
   boundary, but no ptrace escape class either
4. gVisor KVM — hardware VM boundary + syscall interposition; requires nested
   virt or bare metal
5. Full VM (QEMU/KVM) — separate guest kernel, no shared address space at any
   layer

For this setup (VirtualBox dev-box, no `/dev/kvm`), systrap mode is the ceiling.
It is meaningfully stronger than plain Docker for the guest workload, but the
absence of a hardware boundary means it should not be treated as equivalent to
a VM. The `--privileged` flag (or even the narrower capability set above) means
that a Sentry escape still lands in a nearly-unrestricted container, so the
combined security posture depends heavily on trusting the container boundary
itself.

---

## Podman + gVisor inside the privileged container (tested on release-20260601.0)

Podman can be layered between Docker and gVisor, giving you full OCI image
management (pull, layer cache, per-container rootfs) while still running every
container inside a gVisor sandbox:

```
dev-box  (VirtualBox VM)
  └── Docker privileged container  (--cgroupns=host)
        └── Podman
              └── gVisor (runsc) sandbox
                    └── container process
```

### One-time setup

```bash
# 1. Create the outer container — note --cgroupns=host (required, see below)
docker run -d --privileged --cgroupns=host --name gvisor-sandbox ubuntu:22.04 sleep infinity

# 2. Install runsc (same steps as above) then install Podman
docker exec gvisor-sandbox apt-get install -y podman

# 3. Configure Podman to use cgroupfs and register runsc as a runtime
docker exec gvisor-sandbox bash -c '
  mkdir -p /etc/containers
  cat > /etc/containers/containers.conf <<EOF
[engine]
cgroup_manager = "cgroupfs"
events_logger = "file"

  [engine.runtimes]
  runsc = [
    "/usr/bin/runsc",
    "--network=none"
  ]
EOF
'
```

### Running containers through Podman → gVisor

```bash
# Verify the sandbox kernel (should print 4.19.0-gvisor)
docker exec gvisor-sandbox \
  podman run --runtime=runsc --rm alpine cat /proc/version

# Run a Node.js script
docker exec gvisor-sandbox \
  podman run --runtime=runsc --rm node:20-alpine \
  node -e "console.log(require('fs').readFileSync('/proc/version','utf8').trim())"
```

### Why `--cgroupns=host` is required

cgroupv2 places a Docker container at a **leaf cgroup node**. Podman needs to
write to `cgroup.subtree_control` to create sub-cgroups for conmon and the
container process; at a leaf node that write fails with `device or resource busy`.

`--cgroupns=host` shares the host cgroup namespace with the container so Podman
sees a non-leaf node and can create its own sub-cgroups. Without it, Podman
exits with:

```
error creating cgroup path /libpod_parent/conmon: write /sys/fs/cgroup/cgroup.subtree_control: device or resource busy
```

Note: `--cgroups=disabled` (Podman flag) does **not** work around this — Podman
refuses that flag when an external OCI runtime is in use.

### What Podman adds over plain `runsc do`

| Capability | `runsc do` | Podman + runsc |
|---|---|---|
| OCI image pull / layer cache | No — binaries copied manually | Yes |
| Separate rootfs per container | Manual `--root` setup required | Automatic |
| Resource limits | Docker-level only | Podman-level (cgroupfs) |
| Multiple concurrent sandboxes | Possible but manual | First-class |
