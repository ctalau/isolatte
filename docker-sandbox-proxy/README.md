# Docker Sandbox Proxy

Two-container Docker sandbox where all egress from the sandboxed container is
routed through a [Smokescreen](https://github.com/stripe/smokescreen) HTTPS
proxy that enforces a domain allowlist.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  public network                                     │
│     ┌──────────────────────┐                        │
│     │  proxy (Smokescreen) │◄── ACL: npm, maven,    │
│     │  :4750               │    apt, docker, openai, │
│     └──────────┬───────────┘    anthropic            │
│                │                                     │
├────────────────┼────────────────────────────────────┤
│  internal net  │  (no external connectivity)         │
│     ┌──────────┴───────────┐                        │
│     │  sandbox (Ubuntu)    │                        │
│     │  https_proxy=proxy   │                        │
│     │  /workspace mounted  │                        │
│     └──────────────────────┘                        │
└─────────────────────────────────────────────────────┘
```

- **proxy** — connected to both `internal` and `public` networks. Runs a
  custom Smokescreen binary that enforces `acl.yaml`.
- **sandbox** — connected to `internal` only. All HTTP(S) traffic must go
  through the proxy. Direct internet access is impossible.

## Allowed domains

See [`acl.yaml`](acl.yaml) — npm, Maven Central, APT/Ubuntu, Docker Hub,
OpenAI, Anthropic/Claude, Apache mirrors, PyPI, GitHub.

## Quick start

```bash
# Run tests with Docker directly on the host
./run_tests.sh

# Run inside a QEMU software-emulated VM (full isolation)
./run_qemu_tests.sh
```

## Test suites

### Escape tests (`test_escape.sh`)

1. **Direct internet bypass** — verifies curl/wget/TCP/ping fail without proxy
2. **Proxy ACL enforcement** — blocked domains (google.com, evil.com, raw IPs,
   cloud metadata 169.254.169.254)
3. **Allowed domains** — npm, Maven Central, Anthropic, OpenAI reachable
4. **Container escape vectors** — Docker socket, mount, modprobe, sysrq,
   PID namespace, chroot, raw sockets
5. **DNS exfiltration** — direct DNS resolution of arbitrary domains blocked

### Maven test (`test_maven.sh`)

Installs OpenJDK 21 + Maven inside the sandbox, creates a minimal POM that
depends on Guava 33.4.0-jre, resolves the dependency through the proxy, and
verifies the JAR lands in `~/.m2/repository`.

## QEMU mode

`run_qemu_tests.sh` downloads an Ubuntu Noble cloud image and boots it in
QEMU **without KVM** (pure software emulation). The project directory is
shared via virtio-9p. Docker is installed via cloud-init and the full test
suite runs inside the VM. This provides an additional isolation layer — even
a successful container escape only reaches the VM, not the real host.
