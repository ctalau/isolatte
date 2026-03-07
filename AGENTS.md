# Repo structure

Each top-level folder is a self-contained experiment or research artifact. Do not mix content between folders.

## Experiments

- **bwrap-seccomp** — bubblewrap sandbox with a custom seccomp-BPF syscall filter
- **nsjail-dita** — nsjail jail for DITA-OT processing with namespace isolation and capability drops
- **smokescreen-proxy** — egress ACL enforcement via Stripe's Smokescreen proxy over a veth pair
- **podman-node-v10** — baseline podman setup for a constrained Node v10 container environment
- **jenkins-container** — Jenkins CI inside a udocker container with isolated repos and restricted auth

## Security research

- **jgit-vuln-research** — unauthenticated path-traversal vulnerabilities in JGit Protocol V2
- **jgit-security** — additional JGit security analysis including bare repo escape
- **openjdk-analysis** — audit of the OpenJDK `java.lang` module (native methods, Unsafe, reflection)
- **jvm-sandbox-analysis** — JVM and DITA-OT third-party dependency analysis

## Networking

- **podman-container-networking** — podman container networking experiments and test results
