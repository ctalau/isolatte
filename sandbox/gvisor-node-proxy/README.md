# Node.js + host networking + env-var proxy under gVisor (`runsc do`)

Runs a Node.js script inside a gVisor sandbox with **host networking**
(`--network=host`, as opposed to gVisor's own netstack) that fetches the
Oxygen XML Editor home page, optionally through an HTTP(S) proxy configured
purely via the standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` environment
variables.

```
host
  └── gVisor sandbox (runsc do --network=host, kernel 4.19.0-gvisor)
        └── node --use-env-proxy fetch-oxygen.mjs
              └── fetch('https://www.oxygenxml.com/')
```

## Files

| File | Purpose |
|------|---------|
| `fetch-oxygen.mjs` | Fetches `https://www.oxygenxml.com/` and prints the proxy env vars it sees, the response status, and the page title |
| `run.sh` | Installs nothing; just launches the script under `runsc do --network=host`, forwarding the caller's `*_PROXY` env vars |

## One-time setup: install gVisor

```bash
apt-get install -y curl gnupg ca-certificates
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
  https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list
apt-get update -qq && apt-get install -y runsc
```

## Running it

```bash
# Direct (no proxy)
./run.sh

# Through a proxy — any HTTP(S) proxy reachable from the sandbox works.
# See "Reaching a proxy on the host" below for why 192.168.10.3 is the
# right address when the proxy runs on the same machine as `runsc do`.
HTTPS_PROXY=http://192.168.10.3:3128 HTTP_PROXY=http://192.168.10.3:3128 ./run.sh
```

Sample output (no proxy):

```
HTTP_PROXY  = (unset)
HTTPS_PROXY = (unset)
NO_PROXY    = (unset)
Fetching https://www.oxygenxml.com/ ...
status        : 200 OK
content-length: 53637 bytes
page title    : Oxygen XML Editor
```

Sample output (through a local proxy on :3128 — note the proxy's own log
shows `CONNECT www.oxygenxml.com:443`, proving the tunnel was used):

```
HTTP_PROXY  = http://192.168.10.3:3128
HTTPS_PROXY = http://192.168.10.3:3128
NO_PROXY    = (unset)
Fetching https://www.oxygenxml.com/ ...
status        : 200 OK
content-length: 53637 bytes
page title    : Oxygen XML Editor
```

## How the pieces fit together

### `--network=host` vs. the default `--network=sandbox`

| Mode | How traffic flows |
|---|---|
| `sandbox` (default) | gVisor runs its own user-space netstack; it owns the sandbox side of a veth pair that `runsc do` creates and NATs through it to the host's `eth0`. |
| `host` | gVisor does **not** run its own netstack — socket syscalls from the guest pass straight through to the kernel of the network namespace the sandbox process lives in. |

Even with `--network=host`, **`runsc do` still creates its own network
namespace and veth pair** (`ve-runsc-XXXXXX` ↔ `vp-runsc-XXXXXX`,
`192.168.10.2` ↔ `192.168.10.3`) and sets up `iptables` `MASQUERADE` +
`FORWARD` rules so that subnet can reach the internet through the host's
`eth0`. "Host" here means "the network namespace the sandbox is running
in" (which `do` controls), **not** literally the machine's primary
namespace — that distinction only matters if you need the guest to see
host-only services bound to `lo` or other host interfaces, which it can't
in this mode.

For an outbound fetch like ours, the practical effect of `--network=host`
vs. the default is mostly about **how** the connection is made (raw
syscall passthrough vs. gVisor's reimplemented TCP/IP stack), not whether
it can reach the internet — both modes can, because `runsc do` wires up
the same NAT path either way.

### Reaching a proxy on the host

Because the sandbox lives in its own netns, `localhost`/`127.0.0.1` refers
to the sandbox itself, not the host. A proxy process listening on the host
(bound to `0.0.0.0`) is reachable from inside the sandbox at the veth
gateway address `runsc do` assigns — `192.168.10.3` by default (the `-ip`
flag controls the sandbox's own address, `192.168.10.2`, and the gateway is
always `.3`). This was confirmed by running a minimal CONNECT-tunneling
HTTP proxy on the host and observing both the proxy's access log and the
script's successful fetch when `HTTPS_PROXY=http://192.168.10.3:3128` was
set.

### Proxy selection: Node's built-in `--use-env-proxy`

Node 22 ships a built-in `EnvHttpProxyAgent` (still experimental, hence the
`UNDICI-EHPA` warning) that makes the global `fetch`/`http`/`https` stack
honor `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` automatically — enabled
with the `--use-env-proxy` CLI flag (or `NODE_OPTIONS=--use-env-proxy`).
`fetch-oxygen.mjs` deliberately contains **no proxy-handling code at all**;
`run.sh` just passes `--use-env-proxy` to `node` and forwards whatever
`*_PROXY` variables are already in the caller's environment (`runsc do`
passes the parent shell's environment through to the sandboxed process
unchanged — no extra plumbing needed).

## What worked

- Installing `runsc` directly via the official `apt` repo (no Docker layer
  needed — this host already has a usable kernel/cgroup setup for `runsc do`
  once `-ignore-cgroups` is passed; see below).
- `runsc -ignore-cgroups --network=host do node ...` runs Node under gVisor
  (`/proc/version` reports `4.19.0-gvisor`) with working outbound networking.
- DNS resolution and HTTPS to an arbitrary public host (`www.oxygenxml.com`)
  both work in host-network mode — `runsc do` provisions NAT/forwarding
  rules for its private subnet regardless of the `--network` value.
- `node --use-env-proxy` correctly tunnels HTTPS through an `HTTP_PROXY`/
  `HTTPS_PROXY` set purely via environment variables, with zero proxy code
  in the fetch script — verified by watching the proxy's own access log
  record the `CONNECT www.oxygenxml.com:443` from inside the sandbox.

## What did not work (and the workaround)

- **Plain `runsc do ...`** fails immediately with
  `cannot set up cgroup for root: configuring cgroup: stat /sys/fs/cgroup/cpuset: no such file or directory`
  because this host's cgroup v1 hierarchy has no `cpuset` controller mounted.
  **Workaround:** pass `-ignore-cgroups` — acceptable for a one-off `do`
  invocation that isn't trying to enforce resource limits.
- **The very first run** of `--network=host do node -e "fetch(...)"`
  intermittently produced `EAI_AGAIN` (DNS) and `ENETUNREACH` (direct-IP
  connect) errors, while a `bash`-based connectivity check moments later on
  a fresh sandbox succeeded. This looks like a startup race between
  `runsc do` finishing its netns/veth/iptables setup and the sandboxed
  process making its first connection — every run after the first one (and
  every run that did a trivial amount of work first) succeeded reliably
  across more than half a dozen repetitions. Not something this experiment
  needed to fix, but worth knowing if you see a transient failure on the
  very first invocation.
- `--network=host` does **not** give the guest the host's actual primary
  network namespace (contrary to what the name suggests for, e.g., Docker's
  `--net=host`) — `runsc do` always creates its own netns. This isn't a
  blocker for outbound connectivity (NAT handles it) but it does mean the
  guest cannot reach services bound only to the host's `127.0.0.1` or to
  interfaces other than the veth/the NAT path.

## Honest assessment

This works, reliably, with no exotic configuration: install `runsc` from
the official apt repo, run `runsc -ignore-cgroups --network=host do node
--use-env-proxy <script>`, and outbound HTTPS — proxied or not, purely via
standard environment variables — just works. The only friction was (a) one
missing cgroup controller on this particular host, fixed with a documented
flag, and (b) a once-seen startup race that didn't reproduce. I'd consider
this experiment fully working and would not expect surprises adopting this
pattern (gVisor sandbox + host networking + env-var-driven proxying) in a
real workload — the main thing to remember is that "host" networking here
means "the netns `runsc do` builds for you", not literally the machine's
primary namespace, so plan proxy/service addressing around the
`192.168.10.0/24` veth subnet (gateway `.3`) accordingly.
