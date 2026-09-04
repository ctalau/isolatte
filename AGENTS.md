# Repo structure

Each top-level folder is a self-contained experiment or research artifact. Do not mix content between folders.

## Experiments

- **bwrap-seccomp** — bubblewrap sandbox with a custom seccomp-BPF syscall filter
- **nsjail-dita** — nsjail jail for DITA-OT processing with namespace isolation and capability drops
- **smokescreen-proxy** — egress ACL enforcement via Stripe's Smokescreen proxy over a veth pair
- **podman-node-v10** — baseline podman setup for a constrained Node v10 container environment
- **jenkins-container** — Jenkins CI inside a udocker container with isolated repos and restricted auth
- **claude-agent-openrouter-ro** — Claude Agent SDK via OpenRouter using DeepSeek V4 Flash, with a Romanian codeblock translation skill
- **quickjs-bash-sandbox** — the just-bash interpreter running as guest code inside a real QuickJS WASM VM, scoped to a workspace folder via a synchronous fs bridge, benchmarked tarring 1000 files against native `tar`
- **content-fusion-film** — a code-driven cinematic product film for Content Fusion: Remotion + React Three Fiber, a shared camera system driving both CSS-3D and WebGL scenes, Kokoro-generated narration that determines the cut, and a 73.6s 4K master with cutdowns

## Security research

- **jgit-vuln-research** — unauthenticated path-traversal vulnerabilities in JGit Protocol V2
- **jgit-security** — additional JGit security analysis including bare repo escape
- **openjdk-analysis** — audit of the OpenJDK `java.lang` module (native methods, Unsafe, reflection)
- **jvm-sandbox-analysis** — JVM and DITA-OT third-party dependency analysis

## Networking

- **podman-container-networking** — podman container networking experiments and test results

## Agent response expectations

- In status updates and final responses, provide an honest assessment.
- Always include:
  - what worked,
  - what did not work,
  - what you would try next to make it work,
  - and your honest opinion on whether the experiment can be made to work.
- Apply this format to ongoing tasks unless explicitly overridden by the user.
