# Iron-Proxy Egress ACL Experiment

A reimplementation of the [smokescreen-proxy](../smokescreen-proxy) experiment using [iron-proxy](https://github.com/ironsh/iron-proxy) instead of Stripe's Smokescreen. The same three properties are verified:

1. A podman container with `--network=none` and no default route **cannot** reach the internet directly.
2. The container **can** reach `example.com` through the proxy.
3. The proxy **denies** access to any domain not in the allowlist (`google.com` used as the control).
4. Zero iptables rules are created by the entire setup.

## How iron-proxy differs from smokescreen

| | smokescreen | iron-proxy |
|---|---|---|
| TLS handling | CONNECT tunnel (no termination) | MITM / TLS termination |
| Client requirement | Nothing extra | Must trust iron-proxy CA cert |
| Domain ACL source | `acl.yaml` with roles | YAML `transforms.allowlist` |
| DNS server | No | Built-in on `:5353` |
| Secret injection | No | Yes (proxy tokens → real creds) |
| Default policy | Configurable per-role | Default-deny out of the box |

Because iron-proxy terminates TLS, it generates leaf certificates on the fly signed by a CA you provide. The container needs to trust that CA. The experiment generates a self-signed CA with `openssl`, then passes `--ca-certificate` to `wget` for the in-container tests.

## Network topology

```
┌──────────────────────────────────────────────────────────────┐
│ Host Network Namespace                                        │
│                                                              │
│  iron-proxy (0.0.0.0:4750 HTTP proxy, 0.0.0.0:5353 DNS)     │
│       │  allowlist: only example.com (default-deny)          │
│       │  CA: /tmp/iron-proxy-ca.{crt,key}                    │
│       │                                                      │
│  veth-iron-host (10.77.1.1/24)  ──► Internet                │
│       │                                                      │
│       │  veth pair (L2, no iptables, no NAT)                 │
│       │                                                      │
├───────┼──────────────────────────────────────────────────────┤
│       │  Container Network Namespace (podman --net=none)      │
│  veth-iron-client (10.77.1.2/24)                             │
│       │                                                      │
│  - No default route → cannot reach internet directly         │
│  - Can only reach 10.77.1.0/24                              │
│  - Trusts iron-proxy CA for MITM TLS inspection              │
└──────────────────────────────────────────────────────────────┘
```

## Configuration (`config.yaml`)

```yaml
dns:
  listen: ":5353"
  proxy_ip: "10.77.1.1"     # resolve all domains to the proxy itself

proxy:
  http_listen: ":4750"      # standard HTTP CONNECT proxy port
  https_listen: ":4751"

tls:
  ca_cert: "/tmp/iron-proxy-ca.crt"
  ca_key:  "/tmp/iron-proxy-ca.key"

transforms:
  - name: allowlist
    config:
      domains:
        - "example.com"     # only this domain is allowed; everything else → 403
```

## Run

```bash
cd iron-proxy
./run_experiment.sh
```

The script:

1. Downloads the pre-built `iron-proxy` binary from GitHub Releases.
2. Generates a self-signed CA certificate with `openssl`.
3. Writes a runtime config (`/tmp/iron-proxy-config.yaml`) pointing at the generated CA.
4. Snapshots iptables before the experiment.
5. Creates a `veth` pair: `veth-iron-host` (10.77.1.1) on the host, `veth-iron-client` (10.77.1.2) in the container.
6. Starts `iron-proxy` bound to `0.0.0.0:4750`.
7. Starts an alpine container with `--network=none`, moves the veth into its namespace, and adds no default route.
8. Runs three `wget` tests from inside the container's network namespace via `nsenter`.
9. Compares iptables state before and after to confirm no rules were added.

## What worked / What did not / Assessment

### What worked

- **Architecture parity**: The veth + no-default-route isolation pattern maps cleanly onto iron-proxy. The proxy listens on the host side of the veth; the container reaches only the proxy subnet.
- **Config simplicity**: iron-proxy's single YAML file (allowlist transform) is simpler than smokescreen's role-based `acl.yaml`. There is no need for a Go wrapper binary to override `RoleFromRequest` — anonymous connections are accepted by default.
- **DNS capability**: iron-proxy's built-in DNS server on `:5353` can redirect all name resolutions to the proxy IP, enabling a path toward transparent proxying without `HTTPS_PROXY` env vars.

### What did not work / Caveats

- **CA trust in containers**: Because iron-proxy terminates TLS (unlike smokescreen's CONNECT tunnel), every client must explicitly trust the generated CA. In the experiment this is handled by passing `--ca-certificate` to `wget`. For real workloads the CA must be baked into the container image or injected at runtime via a volume mount.
- **Binary availability**: The script fetches the binary from GitHub Releases at runtime. If the release naming convention or architecture identifiers change, the download URL derivation (via `grep` on the GitHub API response) will break.
- **DNS enforcement not used**: The built-in DNS server is configured but not enforced in this experiment. Without nftables DNAT rules redirecting UDP/53 traffic from the container to `10.77.1.1:5353`, a container could use a hardcoded resolver to bypass the domain allowlist. The veth subnet isolation (no default route) is the primary enforcement mechanism here.

### What to try next

1. **nftables DNAT for DNS**: Add an nftables rule to redirect all UDP port 53 from the container's veth to `10.77.1.1:5353`, then rely on iron-proxy's DNS to enforce domain ACLs rather than the allowlist transform alone.
2. **TPROXY mode**: iron-proxy supports kernel TPROXY for fully transparent interception (catches hardcoded IPs). Adding `CAP_NET_ADMIN` to the runner and the appropriate `ip route` rules would close the hardcoded-IP bypass.
3. **Secret injection**: Test iron-proxy's `secrets` transform — configure the container to hold a worthless proxy token, and verify that iron-proxy swaps it for the real credential at the proxy boundary before forwarding upstream.
4. **Image-baked CA**: Build a container image that trusts the iron-proxy CA cert in its system store so no per-request `--ca-certificate` flag is needed.

### Honest assessment

The iron-proxy approach is **viable and in some ways simpler** than smokescreen for this use case. The default-deny policy and single-file YAML config reduce boilerplate. The TLS termination capability is a genuine advantage for inspection and secret injection, though it adds the CA-distribution problem that smokescreen avoids entirely. The experiment can be made fully working; the main gaps are DNS enforcement and the CA trust bootstrapping.
