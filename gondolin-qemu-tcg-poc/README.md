# gondolin-qemu-tcg-poc

Proof-of-concept: run untrusted JavaScript inside a QEMU microVM using
[Gondolin](https://github.com/earendil-works/gondolin) in software-emulation
(TCG) mode, with transparent host-function calls over a JSON-RPC channel on
the exec stdin/stdout stream.

No `/dev/kvm` required.

---

## Design

```
main Node.js process
  ├─ allowedHostFunctions: add(), lookup()
  ├─ Gondolin VM  (QEMU, -accel tcg, ephemeral rootfs)
  │    └─ /scratch/runner.js  (Node.js, injected at runtime)
  └─ JSON-RPC bridge: @@HOSTRPC@@ / response lines over exec stdin/stdout
```

The guest runner wraps user code in an async IIFE and installs a global
`host` Proxy. Any `host.fn(args)` call serialises a JSON-RPC request to
stdout; the host parses it, calls the matching allow-listed function, and
writes the response back to stdin. The guest readline resolves the pending
Promise and user code resumes.

---

## Gondolin API surface used (v0.5.0)

| What | How |
|------|-----|
| Force TCG | `sandbox: { accel: "tcg" }` inside `VM.create()` options |
| Ephemeral root disk | `rootfs: { mode: "memory" }` |
| In-memory scratch VFS | `vfs: { mounts: { "/scratch": new MemoryProvider() } }` |
| HTTP egress policy | `createHttpHooks({ allowedHosts: [...] })` → pass `httpHooks` + `env` |
| Run a command | `vm.exec(argv, { stdin:true, stdout:"pipe", stderr:"pipe" })` |
| Write guest script | `vm.fs.writeFile(path, content)` |
| Close VM | `vm.close()` |
| Find QEMU PID | scan `/proc` for `argv[0]` containing `qemu-system` — **`vm.getHostPid()` does not exist in 0.5.0** |

---

## Results

### What worked

- **TCG confirmed** — QEMU spawns with `-accel tcg`; no `/dev/kvm` required.
- **Guest image ships Node.js** — Gondolin's default Alpine-based image
  (`gondolin-guest-x64.tar.gz`, v0.5.0, ~98 MB) includes Node.js at
  `/usr/bin/node`. No `apk add` needed in practice.
- **JSON-RPC protocol works** — `host.add({ a:2, b:40 })` returns `42` and
  `host.lookup({ key:"hello" })` returns `"world"`. Computation executes on
  the host; only the call/result crosses the VM boundary.
- **Clean process lifecycle** — sending stdin EOF (`proc.end()`) after
  `@@DONE@@` lets the guest readline close and the Node process exit on its
  own within ~160 ms.

### Timing (cached guest image, no `/dev/kvm`, x86-64 host)

| Checkpoint | +ms from start | Segment |
|------------|---------------|---------|
| `vm_create_start` | 0 ms | — |
| `vm_created` | ~14 ms | VM boot *initiated* |
| `node_check_done` (first exec ready) | ~8 000 ms | **effective boot: ~8 s** |
| `exec_attached` (second exec) | ~7 962 ms | — |
| `first_guest_output` | ~10 470 ms | Node startup in guest: ~2.5 s |
| `guest_code_start` | ~10 470 ms | first user code line |
| `rpc_call_sent_id1_fn_add` (guest) | ~10 485 ms | 15 ms after first line |
| `host_rpc_received_id1_fn_add` | ~10 486 ms | guest→host: **~1 ms** |
| `host_rpc_sent_id1_fn_add` | ~10 488 ms | host fn + reply: **~2 ms** |
| `rpc_response_received_id1` (guest) | ~10 566 ms | host→guest: **~78 ms** (first call, TCG JIT cold) |
| `rpc_response_received_id2` (guest) | ~10 581 ms | host→guest: **~7 ms** (second call, JIT warm) |
| `guest_done_marker` | ~10 590 ms | — |
| `exec_completed` | ~10 753 ms | guest process exit: ~163 ms |
| `vm_closed` | ~10 846 ms | VM shutdown: ~93 ms |
| **Total** | **~10.8 s** | cold start → result |

The 78 ms vs 7 ms discrepancy in host→guest response latency is TCG JIT
warm-up: the first time Node's event-loop machinery runs under TCG it
translates more basic blocks; subsequent passes hit the translation cache.

### What did not work / issues found

1. **`vm.getHostPid()` is not part of Gondolin 0.5.0.** The instructions
   reference this method, but it does not appear in the public API. QEMU PID
   inspection requires scanning `/proc` and filtering for `argv[0]` containing
   `qemu-system`. (A naive `pgrep -af qemu` matches the parent Claude process
   itself, which mentions "qemu" in its `--allowed-tools` list.)

2. **Cold start is ~10 s, not 1–2 s.** Boot to first-exec-ready is ~8 s; then
   Node starts in ~2.5 s on top. The 1–2 s target is realistic only with KVM.
   Under TCG the only paths to sub-2 s are:
   - **Gondolin disk checkpoints** (`vm.checkpoint()` / `VmCheckpoint.resume()`):
     checkpoint a warm VM with Node already started; resume adds a qcow2
     overlay, which is cheap.
   - **Replace Node with QuickJS** in a minimal Alpine init — QuickJS under TCG
     starts much faster because the binary is smaller.
   - **Pre-warmed VM pool**: keep N VMs ready; replenish after each use.

3. **Guest readline keeps process alive after user code finishes.** The readline
   interface blocks on stdin, so the guest Node process does not exit after
   emitting `@@DONE@@`. Fix: call `proc.end()` (sends EOF on exec stdin) from
   the host as soon as `@@DONE@@` is received.

4. **VM.create() returns before the VM is bootable.** The promise resolves in
   ~14 ms, but the VM is not ready for exec until ~8 s later. QEMU PID
   inspection must happen after at least one exec has completed.

---

## Running the PoC

```bash
# Requires QEMU (no /dev/kvm needed):
sudo apt-get install -y qemu-system-x86 qemu-utils

npm install
node poc.mjs
```

Expected output on stdout:
```
[guest] {"sum":42,"val":"world"}
```

Expected stderr ends with:
```
Final exit code: 0
```

Guest assets (~98 MB) are cached in `~/.cache/gondolin/v0.5.0` after the
first run.

---

## Honest verdict

**The experiment can be made to work**, but the 1–2 s cold-start target
requires either KVM or a pre-warmed snapshot. With TCG + full Node.js,
~10 s is the realistic floor on a modern x86-64 host. The JSON-RPC RPC
mechanism is solid: the protocol is simple, latency is dominated by TCG JIT
warm-up on the first call (not by the channel itself), and the host-side
isolation model (allow-list of synchronous functions) is the right shape for
a sandboxed interpreter.

**What I would try next:**
1. Use `vm.checkpoint()` after the first boot (with Node running) to snapshot
   the warm state. Subsequent runs do `VmCheckpoint.resume()` which overlays
   the snapshot — startup becomes O(ms) instead of O(seconds).
2. Build a minimal Alpine init that launches QuickJS instead of Node, cutting
   the per-exec startup cost under TCG substantially.
3. If sub-100 ms start is required, combine a pre-warmed pool (3–5 VMs idle)
   with disk checkpoints so each VM is discarded after one run.
