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
  custom Smokescreen binary that enforces `acl.yaml`. Optionally chains through
  an upstream proxy via `UPSTREAM_PROXY_URL`.
- **sandbox** — connected to `internal` only. All HTTP(S) traffic must go
  through the proxy. Direct internet access is impossible. Capabilities are
  dropped (`cap_drop: ALL` with a minimal allowlist).

## Allowed domains

See [`acl.yaml`](acl.yaml) — npm, Maven Central, APT/Ubuntu, Docker Hub,
OpenAI, Anthropic/Claude, Apache mirrors, PyPI, GitHub.

## Quick start

```bash
# Run tests with Docker directly on the host
./run_tests.sh

# With an upstream proxy (e.g., in a sandboxed CI environment)
UPSTREAM_PROXY_URL=http://user:pass@proxy.host:port ./run_tests.sh

# Full QEMU isolation (software emulation, no KVM)
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
verifies the JAR lands in `~/.m2/repository`. Handles TLS-intercepting proxies
by auto-importing the inspection CA into Java's truststore.

## Test results

```
=== Sandbox Escape & Proxy-Bypass Tests ===

── Direct internet access (should all fail) ──
  [TEST 01] Direct curl to google.com (no proxy)                    PASS
  [TEST 02] Direct wget to example.com (no proxy)                   PASS
  [TEST 03] Direct TCP connect to 8.8.8.8:53 via /dev/tcp           PASS
  [TEST 04] Direct ping to 8.8.8.8                                  PASS

── Proxy ACL enforcement (blocked domains) ──
  [TEST 05] Proxy blocks google.com                                 PASS
  [TEST 06] Proxy blocks evil.com                                   PASS
  [TEST 07] Proxy blocks raw IP 1.1.1.1                             PASS
  [TEST 08] Proxy blocks metadata endpoint 169.254.169.254          PASS

── Allowed domains (should succeed via proxy) ──
  [TEST 09] Proxy allows registry.npmjs.org                         PASS
  [TEST 10] Proxy allows repo1.maven.org                            PASS
  [TEST 11] Proxy allows api.anthropic.com                          PASS
  [TEST 12] Proxy allows api.openai.com                             PASS

── Container escape attempts (should all fail) ──
  [TEST 13] Cannot access Docker socket                             PASS
  [TEST 14] Cannot mount host filesystems via mount                 PASS
  [TEST 15] Cannot load kernel modules                              PASS
  [TEST 16] Cannot write to /proc/sysrq-trigger                     PASS
  [TEST 17] Cannot access host PID namespace (PID 1 is container init) PASS
  [TEST 18] Cannot chroot escape                                    PASS
  [TEST 19] No NET_RAW capability (raw sockets blocked)             PASS

── DNS exfiltration attempts ──
  [TEST 20] Cannot resolve arbitrary domains directly               PASS

Results: 20/20 passed

=== Maven Install & Guava Download Test ===

BUILD SUCCESS — Guava 33.4.0-jre (3.0 MB) downloaded through proxy chain
```

## Upstream proxy chaining

When running in an environment that already has an egress proxy (e.g., CI
containers), set `UPSTREAM_PROXY_URL` to the full proxy URL including
credentials:

```
UPSTREAM_PROXY_URL=http://user:token@proxy:port
```

Smokescreen chains through this upstream proxy for both HTTP and HTTPS
traffic. A passthrough DNS resolver is used (the upstream proxy handles DNS
resolution), and the `UpstreamProxyConnectReqHandler` injects
`Proxy-Authorization` for CONNECT tunnels.

## Security hardening

- **Network isolation**: sandbox is on an internal-only Docker network
- **Capability dropping**: `cap_drop: ALL` with minimal allowlist (no
  `NET_RAW`, `SYS_ADMIN`, `SYS_MODULE`, etc.)
- **Link-local denial**: `--deny-range 169.254.0.0/16` blocks cloud metadata
  access
- **CGNAT denial**: `--deny-range 100.64.0.0/10` blocks carrier-grade NAT
- **Private range allowance**: `--unsafe-allow-private-ranges` is enabled for
  internal Docker networking; the deny rules above override this for sensitive
  ranges

## QEMU mode

`run_qemu_tests.sh` downloads an Ubuntu Noble cloud image and boots it in
QEMU **without KVM** (pure software emulation). The project directory is
shared via virtio-9p. Docker is installed via cloud-init and the full test
suite runs inside the VM. This provides an additional isolation layer — even
a successful container escape only reaches the VM, not the real host.
