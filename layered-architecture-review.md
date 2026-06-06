# Layered Architecture Review

## Scope

This document reviews the architecture implied by `PRD.md` against the actual
experiments in the repository. No `layered-architecture.md` file exists; this
review treats `PRD.md` as the authoritative architectural specification and
evaluates each experiment folder against it.

---

## Intended Layered Architecture (from PRD.md)

The PRD describes a three-tier model:

```
┌─────────────────────────────────────┐
│  Layer 1 — Manager Container        │  non-privileged; submits jobs, reads results
│  (API client)                       │
└───────────────┬─────────────────────┘
                │  Control API  (FR1, FR7)
┌───────────────▼─────────────────────┐
│  Layer 2 — Host-Side Runtime        │  privileged at install time only;
│  (sandbox orchestrator)             │  workspace binding, concurrency, lifecycle
└───────────────┬─────────────────────┘
                │  spawn / enforce
┌───────────────▼─────────────────────┐
│  Layer 3 — Sandbox Execution        │  per-job isolation sub-layers:
│  ├── 3a. Filesystem isolation       │    read-only root + writable workspace only
│  ├── 3b. Network enforcement        │    egress-only via approved proxy
│  ├── 3c. Resource control          │    CPU + memory + disk + timeout
│  └── 3d. Process-tree containment  │    all children in same sandbox unit
└─────────────────────────────────────┘
```

Key constraints from the PRD:
- Manager container must **not** mount the host Docker socket.
- Routine operation must be **non-root**.
- Workspaces must **not** be copied (multi-GiB).
- Disk quotas, CPU, memory, and wall-clock timeout are all **mandatory**.
- Egress must be **enforced by the system**, not environment variables.

---

## Package Inventory and Coverage

| Folder | Mechanism | 3a FS | 3b Net | 3c Resources | 3d PID tree | Layer 2 API | Layer 1 |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `bwrap-seccomp` | bwrap + seccomp-BPF | ✅ | ⚠️¹ | ❌ | ❌ | ❌ | ❌ |
| `nsjail-dita` | nsjail + prlimit + taskset | ✅ | ✅ | ⚠️² | ✅ | ❌ | ❌ |
| `smokescreen-proxy` | veth + Smokescreen | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `docker-sandbox-proxy` | Docker Compose + Smokescreen | ⚠️³ | ✅ | ⚠️⁴ | ❌ | ❌ | ❌ |
| `iron-proxy` | bwrap + Unix socket + iron-proxy | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| `podman-node-v10` | Podman (baseline) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `jenkins-container` | udocker + Jenkins | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `sandbox/claude-code` | Docker + bwrap | ⚠️⁵ | ❌ | ❌ | ❌ | ❌ | N/A |

¹ Network blocked via seccomp `socket()` deny — no egress proxy; workloads needing allowed outbound cannot be served.  
² Address-space limit (1 GiB `RLIMIT_AS`) and FD cap, not wall-clock timeout, memory RSS, or disk quota.  
³ Standard container filesystem; no workspace-scope restriction within the container.  
⁴ Capability drops applied to the sandbox container, but no per-job CPU/memory/disk limits.  
⁵ Isolation is for Claude Code's own sub-processes, not for untrusted user workloads.

---

## Findings

### F1 — Layer 2 (Control API) Does Not Exist

**Severity: Critical — blocks PRD delivery**

No experiment or module implements the interface between the manager container
(Layer 1) and the host-side runtime (Layer 2). There is no job submission
protocol, no workspace identifier mapping, no lifecycle management, and no
result-reporting channel. The PRD devotes seven functional requirements
(FR1–FR8) to this layer. Nothing in the repo addresses them.

All experiments are invoked directly via shell scripts from the same machine
that runs the workload, collapsing Layers 1 and 2 into a single operator
session. This makes them useful as component-level research but means the
PRD's core deployment model — manager container talks to host daemon — has
no prototype at all.

### F2 — Layer 1 / Manager Container Absent

**Severity: Critical**

The PRD's primary constraint is that the manager must be a non-privileged
container that cannot mount the host Docker socket. No experiment models this
boundary. Privilege requirements (e.g., `CAP_SYS_ADMIN` for bwrap, `--privileged`
for gVisor) are placed on the same process that controls the workload. A real
implementation needs these capabilities scoped to the host-side runtime only,
invisible to the manager.

### F3 — Disk Quota Enforcement Is Completely Missing

**Severity: High — mandatory PRD requirement**

The PRD lists disk as a required resource limit (FR5). No experiment implements
disk quota. The PRD itself notes this as a risk ("may depend on underlying host
filesystem capabilities"), but none of the research folders explore it — not
XFS project quotas, not overlay quota options, not tmpfs size limits. The
`Technology.md` lists "xfs project quota" as a candidate technology but it has
never been tested.

### F4 — Resource Control Is Partial Across Experiments

**Severity: High**

The PRD requires CPU, memory, disk, and wall-clock timeout enforcement per job.

| Limit | Best coverage found | Gap |
|---|---|---|
| CPU | `taskset` (nsjail-dita) pins to one core | No cgroup CPU quota; pinning ≠ throttling |
| Memory RSS | Not implemented anywhere | `RLIMIT_AS` (address space) ≠ RSS; swap can hide real usage |
| Disk | Not implemented anywhere | See F3 |
| Wall-clock timeout | Not implemented anywhere | `nsjail` has a time limit but it is not externally configurable per-job |

### F5 — Network Enforcement Approaches Are Fragmented With No Convergence

**Severity: Medium**

Three independent network enforcement patterns exist:

| Approach | Folder | Model |
|---|---|---|
| veth pair + no default route | `smokescreen-proxy` | Separate network namespace; proxy on host |
| Docker internal network | `docker-sandbox-proxy` | Internal-only Docker network; proxy sidecar |
| `--unshare-net` + Unix socket pipe | `iron-proxy` | Complete network isolation; proxy over socket |

These are mutually exclusive designs with different deployment models, privilege
requirements, and proxy protocols. `smokescreen-proxy` and `docker-sandbox-proxy`
both use Smokescreen but wire it differently. Neither the README nor any
architecture document records a decision on which approach to carry forward.

The `docker-sandbox-proxy/go.mod` contains a `replace` directive pointing to
`/tmp/smokescreen` (a local filesystem path), making that module unbuildable
in any clean environment. This is an unresolved development artifact.

### F6 — `bwrap-seccomp` Uses a Deny-List Seccomp Policy (Weaker Than Needed)

**Severity: Medium**

`gen_seccomp.c` sets the default action to `SECCOMP_RET_ALLOW` and explicitly
denies a list of syscalls. An allow-list (default deny) policy is significantly
stronger and is the pattern used by gVisor and Docker's default seccomp profile.
Any syscall not on the deny list is implicitly permitted, including future
syscalls added by the kernel. The `sandbox/gvisor-in-docker.md` analysis notes
this distinction explicitly but the `bwrap-seccomp` implementation was not
updated to reflect it.

### F7 — `jenkins-container` Is Outside the PRD Scope

**Severity: Low (catalogue issue)**

`jenkins-container` sets up a Jenkins CI environment inside udocker. It has no
relationship to the PRD's sandboxing requirements. The `AGENTS.md` categorises
it as an "experiment" alongside the sandboxing work, which may create confusion
when reading the repo as a whole. It is more accurately described as
infrastructure-for-testing than a sandboxing building block.

### F8 — `podman-node-v10` Baseline Targets Kernel 4.4, Contradicting PRD Assumptions

**Severity: Low**

The PRD assumes `systemd` is available and targets modern Linux hosts. `podman-node-v10`
exists specifically to document constraints on kernel 4.4 (no overlay filesystem,
no netavark, `cni` network backend only). These constraints do not apply to any
PRD-conforming deployment. The folder is useful historical context but its
conclusions are inapplicable to the target environment and should not influence
the design.

### F9 — `sandbox/` Is a Mixed-Purpose Directory

**Severity: Low (structural issue)**

`sandbox/gvisor-in-docker.md` and `sandbox/gvisor-eks.md` are analysis documents
without a corresponding experiment folder at the top level. `sandbox/claude-code/`
is a launcher for Claude Code itself — a developer tool, not an untrusted-workload
sandbox. Grouping them under `sandbox/` implies they are sibling implementations
of the same concept, which they are not. Per `AGENTS.md`, each top-level folder
should be a self-contained experiment; the gVisor analysis documents belong in a
dedicated `gvisor-analysis/` folder.

### F10 — Process-Tree Containment Is Only Addressed by nsjail

**Severity: Medium**

The PRD (FR3) requires that all child processes of a sandboxed job share the same
limits and are terminated together. Only `nsjail-dita` addresses this via a PID
namespace. `bwrap-seccomp` creates a PID namespace but does not demonstrate
coordinated teardown. `docker-sandbox-proxy` and `smokescreen-proxy` rely on
container lifecycle (cgroup-based teardown), which is adequate for Docker-based
approaches but is not present in the non-Docker experiments.

---

## Cross-Package Dependencies

All experiment folders are self-contained with no imports or code sharing between
them (confirmed: no cross-package Go imports, no relative JS imports across
folders). This matches the `AGENTS.md` requirement ("Do not mix content between
folders").

One structural dependency exists outside the experiments:
- `docker-sandbox-proxy/go.mod` replaces `github.com/stripe/smokescreen` with
  a local path `/tmp/smokescreen`. This is not a dependency on another folder in
  the repo, but it makes the module unresolvable in a fresh checkout and should
  be replaced with a pinned version reference or an explicit vendor directory.

---

## Summary Table

| Finding | Area | Severity | PRD Reference |
|---|---|---|---|
| F1 — No Layer 2 control API | Architecture | **Critical** | FR1, FR2, FR7, FR8 |
| F2 — No Layer 1 manager separation | Architecture | **Critical** | System Constraints |
| F3 — Disk quotas not explored | Resource control | **High** | FR5 |
| F4 — CPU/memory/timeout partial | Resource control | **High** | FR5, FR6 |
| F5 — Network enforcement fragmented | Network layer | **Medium** | FR4 |
| F6 — Deny-list seccomp in bwrap-seccomp | Sandbox layer | **Medium** | FR3 |
| F7 — jenkins-container out of scope | Catalogue | **Low** | Out of scope |
| F8 — podman-node-v10 targets wrong kernel | Baseline | **Low** | Assumptions |
| F9 — sandbox/ mixes doc types | Structure | **Low** | AGENTS.md |
| F10 — PID-tree containment in one experiment only | Sandbox layer | **Medium** | FR3 |

---

## What Would Be Needed to Align With Architecture

1. **Define and prototype the Layer 2 API** — a minimal host-side daemon (systemd
   service or socket-activated binary) that accepts job launch requests from a
   non-privileged manager and returns structured results. The
   `docker-sandbox-proxy` Go structure is the closest starting point.

2. **Implement disk quotas** — pick one mechanism (XFS project quotas, tmpfs
   `size=` limit, or overlay quota options) and test it end-to-end.

3. **Replace `RLIMIT_AS` with cgroup memory limits** — properly enforce RSS via
   cgroup v2 `memory.max`, which `nsjail-dita` already partially scaffolds.

4. **Add wall-clock timeout enforcement** — implement per-job timeout as a
   cgroup-based or systemd transient unit timeout, not just an `nsjail` internal
   limit.

5. **Converge the network enforcement approach** — the `docker-sandbox-proxy`
   pattern (internal-only Docker network + Smokescreen sidecar) is the most
   complete and testable. The `smokescreen-proxy` veth approach is the better
   fit for non-Docker deployments. Document a decision.

6. **Replace the deny-list seccomp in `bwrap-seccomp`** with an allow-list policy
   aligned with the Docker or gVisor baseline.
