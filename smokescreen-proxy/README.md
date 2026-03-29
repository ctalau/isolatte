# Smokescreen Egress Proxy Experiment

A network-isolation experiment that routes all container egress through Stripe's Smokescreen HTTPS proxy instead of iptables NAT. A veth pair connects a podman container (started with `--network=none`) to the host, giving it an IP on a dedicated `/24` subnet with no default route and no internet reachability. Smokescreen runs on the host-side veth IP and enforces a domain ACL (`acl.yaml`) that whitelists only `example.com` in "enforce" mode. `main.go` overrides `RoleFromRequest` so the proxy accepts connections without TLS client certificates. `run_experiment.sh` verifies three properties: the container cannot reach the internet directly, it can reach `example.com` via the proxy, and it is denied access to any non-whitelisted domain — while confirming that zero iptables rules are created by the entire setup.

## Dual-proxy over a Unix pipe (A -> Unix socket -> B -> Internet)

`run_dual_proxy_unix_pipe.sh` builds a 2-proxy chain where:

1. `curl` talks to **Proxy A** on `127.0.0.1:18080`.
2. Proxy A forwards raw proxy traffic over a **Unix socket** (`/tmp/proxy_ab.sock`).
3. **Proxy B** accepts from the Unix socket and forwards to Smokescreen.
4. Smokescreen performs DNS/domain ACL enforcement and only allows `example.com` from `acl.yaml`.

### Run

```bash
cd smokescreen-proxy
./run_dual_proxy_unix_pipe.sh
```

The script runs two tests with `curl -x http://127.0.0.1:18080`:

- `https://example.com` should succeed.
- `https://google.com` should be blocked by Smokescreen ACL.
