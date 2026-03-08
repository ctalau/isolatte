# PRD: Host-Based Sandboxing for Semi-Trusted Workloads

## Document Status
Draft

## Summary
Build a sandboxing system that allows a sandbox manager running inside a non-privileged container to execute semi-trusted Linux process trees on the host machine with strict controls over filesystem access, network egress, resource consumption, and execution lifetime.

The system is intended for customers who already have Docker installed, but the sandboxing solution must not depend on mounting the host Docker socket into the manager container.

---

## Problem Statement
We need to execute semi-trusted workloads on customer-owned Linux machines in a way that is operationally simple, secure by default, and compatible with environments that restrict privileged container integrations.

The current need is not “container orchestration.” The need is controlled execution of process trees with the following guarantees:

1. Workloads may only access an assigned workspace directory.
2. Workloads may not access the Internet directly.
3. All outbound network traffic must go through a designated proxy.
4. Workloads must be constrained by CPU, memory, disk, and wall-clock timeout.
5. The sandbox manager itself runs in a non-privileged container.

---

## Product Goal
Provide a host-executed sandbox runtime that can be controlled by a non-privileged manager container and that safely runs semi-trusted jobs under explicit policy.

---

## Target Users
- Platform teams embedding a sandboxed execution feature into their product
- Customers deploying the system onto their own Linux hosts
- Operators who need predictable controls and low operational overhead

---

## Primary Use Case
A manager container receives a request to run a job against a large existing workspace. It asks the host-side sandbox system to run a process tree with specific limits and proxy settings, then receives status, logs, and exit results.

---

## In Scope
- Running a process tree on Linux hosts
- Enforcing access to a specific assigned workspace
- Enforcing outbound proxy-only networking
- Enforcing CPU, memory, disk, and timeout limits
- Returning job status, exit code, and logs
- Supporting multiple concurrent jobs on one machine
- Operating with a non-privileged manager container

---

## Out of Scope
- Windows support
- macOS support
- Running arbitrary VM workloads
- Exposing inbound ports from sandboxed jobs
- Running jobs as root inside the sandbox
- Full container-image lifecycle management
- Strong multi-tenant isolation against fully hostile adversaries

---

## Key Assumptions
- Target hosts are Linux-only.
- Workloads are semi-trusted, not fully hostile.
- Workloads do not require root privileges.
- Workloads do not need to bind or expose network ports.
- Workloads may spawn child processes and must be treated as a process tree.
- Workspaces may be multiple gigabytes in size, so copy-in/copy-out is not acceptable.
- `systemd` is available on the host.
- A host-side component may perform privileged setup at install time, but routine operation should avoid root and should avoid requiring `CAP_SYS_ADMIN`.
- A small host-side service or helper is acceptable, whether always-on or started on demand.

---

## System Constraints

### Deployment Constraints
- The sandbox manager runs inside a **non-privileged container**.
- The solution must **not require mounting the host Docker socket** into that container.
- The solution does **not have to use Docker** to execute workloads.
- The solution must work on hosts where customers may restrict privileged container patterns.

### Host Platform Constraints
- The solution targets **Linux only**.
- The host environment can be assumed to have **systemd** available.
- The design should tolerate customer environments with conservative security controls.

### Trust and Threat Constraints
- Sandboxed code is **semi-trusted**.
- The system should defend against misuse, escape attempts, and policy bypass by semi-trusted code.
- The system is **not required** to meet the bar for fully hostile, multi-tenant adversaries.
- The design should still prefer conservative defaults and minimize host attack surface.

### Privilege Constraints
- The runtime path should be **non-root during normal operation**.
- Avoid dependence on `CAP_SYS_ADMIN`.
- Root may be used at install time for one-time setup if needed.
- Any ongoing privileged functionality should be narrowly scoped and minimized.

### Execution Constraints
- Each sandbox runs a **small app process tree**, not just a single process.
- Sandboxed jobs do **not** need to run as root.
- Sandboxed jobs do **not** need to open or expose listening ports.
- The system must support **medium concurrency**: on the order of tens of concurrent sandboxes per machine.

### Filesystem Constraints
- Each sandbox must be restricted to a **specific assigned workspace directory**.
- That workspace corresponds to a host-backed path; it must **not** be duplicated into a temporary copy because workspaces may be **multiple gigabytes**.
- The sandbox should not be able to modify files outside the assigned writable workspace.
- The design may expose additional runtime files as read-only if required for program execution, but the writable user-controlled area must remain limited to the assigned workspace.

### Network Constraints
- Sandboxed jobs must reach the Internet **only through a designated proxy**.
- Direct outbound Internet access must be blocked.
- Access to **local/LAN/private network ranges** must also be blocked, except as required to reach the allowed proxy endpoint.
- The network policy must be enforced by the system, not merely suggested through environment variables.

### Resource Constraints
The system must enforce at least the following per-job limits:
- **CPU**
- **Memory**
- **Disk usage**
- **Wall-clock timeout**

These limits must be enforced by the sandboxing system rather than left to workload cooperation.

---

## Functional Requirements

### FR1. Job Launch
The system must accept a request to launch a sandboxed job with:
- workspace identifier
- command and arguments
- environment variables
- resource limits
- timeout
- proxy configuration

### FR2. Workspace Binding
The system must map the job to a specific pre-approved workspace path and ensure the job cannot write outside that workspace.

### FR3. Process Tree Containment
The system must treat the job and all child processes as part of the same sandbox and apply limits and termination consistently to the full process tree.

### FR4. Network Egress Enforcement
The system must enforce that outbound connectivity is possible only via an approved proxy path and must block direct access to other external and private destinations.

### FR5. Resource Enforcement
The system must enforce CPU, memory, disk, and timeout limits per sandbox.

### FR6. Timeout Handling
When a timeout is reached, the system must terminate the full process tree and mark the job as timed out.

### FR7. Result Reporting
The system must return:
- job state
- exit code or termination reason
- timeout status
- basic logs or output handles
- resource-violation reason when applicable

### FR8. Concurrency
The system must safely support tens of concurrent jobs on the same machine without policy leakage across jobs.

---

## Non-Functional Requirements

### Security
- Default-deny posture wherever practical
- No dependency on manager-container access to host Docker socket
- No routine root execution path for normal job launches
- Minimized privileged surface area
- Strong policy enforcement for filesystem and network boundaries

### Reliability
- Failed jobs must clean up their runtime state
- Stale sandboxes must not linger indefinitely
- Partial failures should surface actionable error states

### Performance
- Sandbox startup overhead should be reasonable for interactive or short-running jobs
- Large workspaces must not require copying
- The system should scale to tens of concurrent jobs on a single machine

### Operability
- Installation may perform privileged setup once
- Day-2 operations should be simple to monitor and debug
- Logs and job outcomes should be inspectable by operators

---

## Success Criteria
The system is successful if it can, on a Linux host:

1. Launch a semi-trusted process tree from a non-privileged manager container.
2. Restrict writable access to the assigned workspace only.
3. Prevent direct outbound Internet access.
4. Prevent access to local/private network ranges except for the approved proxy path.
5. Enforce CPU, memory, disk, and timeout limits.
6. Cleanly terminate and report on jobs under normal completion and failure conditions.
7. Sustain tens of concurrent sandboxes without cross-job interference.

---

## Acceptance Criteria
- A job can be launched without access to the host Docker socket.
- A job cannot write outside its assigned workspace.
- A job cannot connect directly to public Internet destinations.
- A job cannot connect to RFC1918/private LAN addresses unless explicitly allowed for proxy routing.
- A job exceeding its CPU, memory, disk, or timeout budget is stopped and reported correctly.
- Multiple concurrent jobs can run with independent limits and isolation.

---

## Risks
- Disk-limit enforcement may depend on underlying host filesystem capabilities.
- Network policy enforcement may require narrow privileged integration on the host.
- Some workloads may implicitly depend on broader filesystem visibility than initially expected.
- Semi-trusted code may still exploit gaps if policy boundaries are not enforced by the host, not just by convention.

---

## Open Questions
1. What exact API should exist between the manager container and the host-side sandbox component?
2. How should workspace identifiers be mapped to host paths safely?
3. What minimum read-only runtime surface is required outside the writable workspace?
4. How should disk quotas behave across nested directories and shared filesystems?
5. What operator-facing observability is required beyond logs and exit status?
6. Are there any customer environments where a small host-side helper with limited privileges is unacceptable?

---
