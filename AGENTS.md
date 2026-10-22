# Repo structure

Each top-level folder is a self-contained experiment or research artifact. Do not mix content between folders.

## Experiments

- **teavm-node-saxon** — TeaVM AOT compilation of Saxon-HE/Xerces for in-memory XSLT execution in Node, with platform adaptations and JVM reference checks
- **teavm-classlib-jvm** — TeaVM's `java.io` classlib patched into a real HotSpot `java.base`, with a TeaVM VirtualFileSystem jailed to one folder; Xerces XInclude works inside it and fails outside

- **teavm-c-xerces** — Xerces-J + XInclude compiled by TeaVM's C backend to a native binary, with `java.io` jailed to one read-only folder (verified with escape tests and strace) and a small-file benchmark against HotSpot

- **bwrap-seccomp** — bubblewrap sandbox with a custom seccomp-BPF syscall filter
- **nsjail-dita** — nsjail jail for DITA-OT processing with namespace isolation and capability drops
- **smokescreen-proxy** — egress ACL enforcement via Stripe's Smokescreen proxy over a veth pair
- **podman-node-v10** — baseline podman setup for a constrained Node v10 container environment
- **jenkins-container** — Jenkins CI inside a udocker container with isolated repos and restricted auth
- **claude-agent-openrouter-ro** — Claude Agent SDK via OpenRouter using DeepSeek V4 Flash, with a Romanian codeblock translation skill
- **quickjs-bash-sandbox** — the just-bash interpreter running as guest code inside a real QuickJS WASM VM, scoped to a workspace folder via a synchronous fs bridge, benchmarked tarring 1000 files against native `tar`
- **content-fusion-film** — a code-driven cinematic product film for Content Fusion: Remotion + React Three Fiber, a shared camera system driving both CSS-3D and WebGL scenes, Kokoro-generated narration that determines the cut, and a 73.6s 4K master with cutdowns
- **dtd-validator-throughput** — DTD-validating all 2,757 Oxygen user guide `.dita` topics: all 42 DITA 1.3/2.0/LwDITA shells compiled to Rust (minimized DFAs + quick-xml, differential-fuzzed against xmllint, and matching plain Xerces-J file for file and error for error on the 3,294 ScriptoriumDev/LearningDITA files) do ~120k files/s on 4 threads, compiled to JS (saxes) ~25k and compiled to Java (JDK SAX) ~16k JIT-warm, and the Rust one built to wasm validates the guide in ~100 ms on 4 Web Workers in a browser page that also reads public GitHub repos when its host allows it; xmloxide (Rust, patched for `xml:*` attributes) with cached flattened DITA DTDs does ~20k files/s on 4 threads, vs libxml2-cached ~12k, Xerces-J with a shared public-ID-keyed grammar pool ~6.7k (JIT-warm), rusty_xml ~470 and stock `xmllint --valid` ~90

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
