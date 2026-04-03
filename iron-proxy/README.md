# Iron-Proxy Egress ACL Experiment (bwrap + Unix-socket pipe)

A reimplementation of [smokescreen-proxy/run_dual_proxy_unix_pipe.sh](../smokescreen-proxy/run_dual_proxy_unix_pipe.sh) using [iron-proxy](https://github.com/ironsh/iron-proxy) instead of Stripe's Smokescreen.

The same two properties are verified:

1. A `bwrap --unshare-net` sandbox has **total network isolation** — no TCP/UDP sockets, no direct internet access.
2. The sandbox **can** reach `example.com` through a Unix socket pipe to iron-proxy (Unix domain sockets are not scoped to network namespaces).
3. iron-proxy **denies** access to any domain not in the allowlist (`google.com` as the control).

## Key insight

`bwrap --unshare-net` puts the sandboxed process in a fresh network namespace with only loopback. It cannot open TCP or UDP sockets to the host. However, Unix domain sockets are filesystem objects, not network objects — they are **not** scoped to network namespaces. Bind-mounting a Unix socket path into the sandbox gives the workload a single, controlled egress channel. iron-proxy sits outside, owning the other end of that socket, and enforces the domain allowlist before forwarding anything upstream.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│ bwrap sandbox (--unshare-net — loopback only)                 │
│                                                               │
│  socat Proxy A: TCP 127.0.0.1:18080 → UNIX /run/proxy.sock   │
│  curl -x http://127.0.0.1:18080 <url> --cacert /run/ca.crt   │
│                                              │                │
│                    (Unix socket bind-mounted in from host)    │
│                                              │                │
└──────────────────────────────────────────────┼────────────────┘
                                               │ ← ONLY egress channel
                    ┌──────────────────────────┘
                    │
   socat Proxy B (host): UNIX-LISTEN /tmp/iron-pipe.sock
                                      → TCP 127.0.0.1:4750
                    │
   iron-proxy (host, 127.0.0.1:4750)
   │  allowlist: only example.com (default-deny)
   │  TLS termination / MITM
   │  CA: /tmp/iron-proxy-ca.{crt,key}
   └──► Internet
```

## Chain

| Step | Component | Direction |
|---|---|---|
| 1 | `curl` inside bwrap | → TCP 127.0.0.1:18080 (loopback, inside sandbox) |
| 2 | socat Proxy A (inside bwrap) | → UNIX `/run/proxy.sock` (bind-mounted) |
| 3 | socat Proxy B (host) | UNIX `/tmp/iron-pipe.sock` → TCP 127.0.0.1:4750 |
| 4 | iron-proxy (host) | enforces allowlist, terminates TLS, forwards upstream |

## iron-proxy vs smokescreen in this topology

| | smokescreen | iron-proxy |
|---|---|---|
| TLS handling | CONNECT tunnel — no termination | MITM — terminates and re-encrypts |
| Client CA trust | Not required | Required (`--cacert` or system store) |
| Binary source | Go wrapper built from `main.go` | Pre-built binary from GitHub Releases |
| ACL format | `acl.yaml` with roles + `RoleFromRequest` override | YAML `transforms.allowlist`, no role config needed |
| DNS server | No | Built-in on `:5353` |
| Secret injection | No | Yes |

## Run

```bash
cd iron-proxy
./run_experiment.sh
```

The script:

1. Downloads the `iron-proxy` pre-built binary from GitHub Releases.
2. Generates a self-signed CA cert with `openssl` (iron-proxy needs this for MITM TLS).
3. Starts `iron-proxy` on `127.0.0.1:4750` with the allowlist restricted to `example.com`.
4. Starts socat **Proxy B** on the host: `UNIX-LISTEN /tmp/iron-pipe.sock` → `TCP 127.0.0.1:4750`.
5. Writes an inner test script that runs socat **Proxy A** (`TCP:18080 → UNIX socket`) and then exercises `curl`.
6. Launches `bwrap --unshare-net` with the Unix socket and CA cert bind-mounted in.
7. Inside bwrap: Proxy A bridges loopback TCP to the Unix socket; curl runs two tests.
8. Parses and reports results.

## What worked / What did not / Assessment

### What worked

- **Architecture parity with smokescreen**: The two-socat chain maps directly — Proxy B (host) bridges the Unix socket to iron-proxy's TCP port; Proxy A (inside bwrap) bridges loopback TCP to the Unix socket. The workload (`curl`) sees a plain HTTP proxy at 127.0.0.1:18080 regardless of which proxy enforces the ACL.
- **No Go wrapper needed**: smokescreen required a custom `main.go` to override `RoleFromRequest` (bypassing TLS client cert auth). iron-proxy accepts anonymous connections by default — drop the binary, write a config, done.
- **Config simplicity**: A single YAML file with an `allowlist` transform replaces smokescreen's role-based `acl.yaml` plus the Go build step.

### What did not work / Caveats

- **CA trust inside bwrap**: Because iron-proxy terminates TLS (unlike smokescreen's CONNECT tunnel), `curl` inside the sandbox must explicitly trust the iron-proxy CA via `--cacert`. The smokescreen version needs no extra trust configuration. The CA cert is bind-mounted into bwrap at `/run/iron-proxy-ca.crt` as a workaround. For real workloads the CA must be baked into the image or injected at build time.
- **Binary availability at runtime**: The script fetches the binary from GitHub Releases. If the release asset naming convention changes, the `grep`-based URL extraction will silently fail.
- **bwrap `--bind` for Unix socket**: bwrap's `--bind src dest` treats the destination as a regular file bind mount. Whether a listening Unix socket survives this depends on the kernel and bwrap version — some versions require the destination to already exist as an empty file (`touch /tmp/placeholder`). If `socat` inside bwrap reports "connection refused", create the destination as an empty file before the bwrap call.

### What to try next

1. **Seal with seccomp**: The bwrap-seccomp experiment blocks `socket(AF_INET/AF_INET6)` via a BPF filter as a belt-and-suspenders measure in environments where `--unshare-net` is unavailable (e.g., rootless Docker). Apply the same seccomp filter here.
2. **Secret injection test**: Configure a dummy `secrets` transform in iron-proxy, pass a proxy token as an env var into bwrap, and verify iron-proxy swaps it for the real credential before forwarding — the token inside the sandbox is worthless if intercepted.
3. **FD-passing instead of bind-mount**: Pass the Unix socket as a file descriptor into bwrap (rather than a bind-mounted path) to avoid the socket-file mount edge case. This is cleaner but requires `bwrap --ro-bind-data` or a small wrapper.
4. **DNS enforcement**: Start iron-proxy's built-in DNS on `:5353`, pass it as the resolver inside bwrap via a custom `resolv.conf` bind mount, and confirm domain-based blocking at the DNS layer in addition to the proxy layer.

### Honest assessment

The reimplementation is **viable and simpler** than the smokescreen version for this topology. The elimination of the Go build step and the `RoleFromRequest` override is a genuine improvement. The main added complexity is CA distribution (a consequence of MITM vs CONNECT), which is a one-time setup cost. The bwrap + Unix socket egress channel pattern works identically regardless of which proxy sits at the other end.
