# isolatte

Security and sandboxing experiments for running untrusted code with granular isolation controls. Each folder represents a distinct approach or research area.

## Sandboxing experiments

- **bwrap-seccomp** — hermetic bubblewrap sandbox hardened with a custom seccomp-BPF syscall filter
- **nsjail-dita** — wraps DITA-OT processing in an nsjail jail with namespace isolation, chroot, capability drops, CPU pinning, and a loopback-only HTTP server
- **smokescreen-proxy** — egress ACL enforcement on a container with no default route using Stripe's Smokescreen proxy over a veth pair
- **iron-proxy** — reimplementation of the smokescreen-proxy experiment using [iron-proxy](https://github.com/ironsh/iron-proxy): MITM/TLS-terminating egress proxy with built-in DNS, default-deny allowlist, and secret injection capability
- **podman-node-v10** — baseline podman script that established the constrained kernel/storage environment all other container experiments built on
- **jenkins-container** — Jenkins CI environment inside a udocker container with isolated git repos and restricted authentication

## Security research

- **jgit-vuln-research** — two unauthenticated path-traversal vulnerabilities in JGit's Protocol V2 parser, full I/O usage analysis, and the responsible-disclosure email
- **jgit-security** — additional JGit security analysis including bare repo escape
- **openjdk-analysis** — security-focused audit of the OpenJDK `java.lang` module covering native methods, Unsafe usage, reflection bypass, and process execution risks
- **jvm-sandbox-analysis** — broader JVM and DITA-OT third-party dependency analysis

## Networking

- **podman-container-networking** — podman container networking experiments, test results, and reproduction instructions
