# quickjs-bash-sandbox

Run bash scripts against a real workspace folder without a real shell: the
script is parsed and interpreted by [`just-bash`](https://github.com/vercel-labs/just-bash)
(a bash implementation written in TypeScript — no `fork`/`exec` of
`/bin/bash`, no arbitrary native binaries), and any JavaScript the script
runs via `js-exec` executes inside an actual [QuickJS](https://bellard.org/quickjs/)
WASM VM (`quickjs-emscripten`), not the host's V8. Filesystem access is
confined to one real directory on disk (the "workspace") via just-bash's
`ReadWriteFs`.

```js
import { BashSandbox } from "./src/bash-sandbox.mjs";

const sandbox = new BashSandbox({ workspace: "/path/to/workspace" });
const result = await sandbox.run('echo "hello" > greeting.txt && cat greeting.txt');
// { stdout: "hello\n", stderr: "", exitCode: 0, durationMs: 12 }
```

That's the whole API surface for the common case: one class, one `workspace`
directory, `run(script)` in, `{ stdout, stderr, exitCode, durationMs }` out.
Files the script writes land on real disk under `workspace`; files already
there are visible to the script.

## Architecture

```
Node.js host process
  └─ BashSandbox (src/bash-sandbox.mjs)
       └─ just-bash Bash instance
            ├─ interprets the bash script in JS (no real shell)
            ├─ ReadWriteFs, root = workspace dir (all paths clamp to root)
            └─ js-exec (opt-in via enableZip) → QuickJS WASM VM
                 └─ fs bridge → same ReadWriteFs, same workspace scope
```

Two layers of isolation, both enforced without OS-level sandboxing
(containers, seccomp, VMs):

1. **just-bash itself**: the bash script never becomes a real process. There
   is a fixed, closed set of built-in commands (`ls`, `grep`, `sed`, `tar`,
   ...); anything not on that list is "command not found", not a shell
   escape. Filesystem access goes through `ReadWriteFs`, which resolves
   every path against the workspace root — traversal (`cd ../../..`,
   absolute paths like `/etc/passwd`) is confirmed in
   `test/bash-sandbox.test.mjs` to clamp at the workspace boundary rather
   than reaching the real filesystem outside it.
2. **js-exec / QuickJS** (opt-in): if a script needs to run JavaScript
   (here, to build a zip archive — see below), it runs inside a real QuickJS
   WASM VM with its own memory limit (64 MB) and execution deadline, wired
   to the *same* workspace-scoped filesystem bridge, not raw Node `fs`.

Network access, Python, and `js-exec` are all off unless explicitly enabled
(matching just-bash's own defaults) — `BashSandbox`'s constructor mirrors
that: nothing beyond core bash commands and workspace file I/O is turned on
by default.

## API

```ts
new BashSandbox({
  workspace: string,          // required: real directory, created if missing
  network?: false | object,   // just-bash NetworkConfig; default: disabled
  enableZip?: boolean,        // turns on js-exec (QuickJS) + the zip helper below
  executionLimitProfile?: "normal" | "hardened", // default: "hardened"
  executionLimits?: object,   // see just-bash README, e.g. maxExecutionTimeMs
})

sandbox.run(script, opts?)         // -> { stdout, stderr, exitCode, durationMs }
sandbox.runFile(relativePath, opts?)
sandbox.zipDirectory(srcDir, destZip) // requires enableZip: true, see below
```

`run()`/`runFile()` accept the same per-call options as just-bash's own
`exec()` (`env`, `cwd`, `stdin`, `signal`, etc. — see the
[just-bash README](https://github.com/vercel-labs/just-bash#readme)).

## The zip benchmark, and what it took to make it correct

The task this experiment was built around: zip 1000 files (2 KB each) using
this sandbox, and compare against invoking the real `zip` binary. The
straightforward plan — read each file inside `js-exec`, hand-build a ZIP
archive with `Buffer`/`Uint8Array`, write it out with
`fs.writeFileSync()` — **did not work**, and chasing down why was most of
the actual effort here. Two real bugs in just-bash 3.2.0's Node-compat shim
for `js-exec`, found by testing, not documented anywhere:

- **Indexed `Buffer` access doesn't work.** `buf[i]` reads back `undefined`
  for every index, and `someUint8Array.set(bufferInstance, offset)` silently
  writes zeros instead of copying the source bytes. A first version of the
  zip helper "worked" (`unzip -t` reported no errors) while silently
  producing an archive of zero-filled, empty-named entries — the CRC-32 we
  computed from the same broken byte access matched the equally-broken
  zeroed-out data we wrote, so the integrity check was checking a
  self-consistent lie.
- **Binary writes truncate at the first embedded `0x00` byte.**
  `fs.writeFileSync()` and `fs.readFileSync(path, encoding)` both stop dead
  at the first NUL byte, as if the data were a C string. A general file's
  bytes will very likely contain one.

The workaround, implemented in `src/zip-bootstrap.mjs`: stay in "byte
string" land (`String.fromCharCode`/`charCodeAt`, one JS char = one byte)
instead of `Buffer` indexing — that path round-trips full binary content
correctly, NUL bytes included. The finished archive is base64-encoded and
returned over `stdout` (a channel that's provably fine with embedded NULs,
since it's text), and the actual `.zip` file is written to disk by the
*trusted host*, not from inside the sandbox. `zipDirectory()` wraps all of
that behind one call. `test/bash-sandbox.test.mjs` includes a test that
round-trips all 256 byte values including `0x00` through a real zip/unzip
cycle to guard against regressing into either bug.

### Results (1000 files x 2 KiB, median of 3 runs)

| Method | Median |
|---|---|
| `BashSandbox.zipDirectory` (QuickJS, store) | 3743 ms |
| native `zip -0` (store — apples-to-apples) | 27 ms |
| native `zip` (default, deflate) | 47.7 ms |

**~139x slower than native `zip -0`.** Full numbers, methodology, and a
"why" in [`results/benchmark-results.md`](results/benchmark-results.md).
Reproduce with `npm run benchmark`.

## Known limitation: process doesn't exit on its own

Once `enableZip`/`javascript` is used, the Node process spawns a
`worker_threads.Worker` per `js-exec` call that is not `unref()`'d — the
host process will not exit on its own afterward. Workarounds used here:
`npm test` runs with `node --test --test-force-exit`, and
`benchmark/zip-benchmark.mjs` ends with an explicit `process.exit(0)`. Any
other script using `enableZip: true` needs the same.

## Running

```bash
npm install
npm test         # 15 tests: exec semantics, workspace confinement,
                  # execution limits, js-exec/QuickJS, zip correctness
npm run benchmark
```

## Honest assessment

**What worked**: the core ask — running bash scripts through a
non-native interpreter, scoped to one real workspace directory, with an
extra QuickJS-sandboxed layer for embedded JavaScript — works as designed
and held up under adversarial testing (path traversal, symlink-to-`/etc/passwd`,
runaway loops, no-network-by-default). The simple `run(script)` API and the
`zipDirectory()` convenience wrapper both do what they say. All 15 tests
pass, including a byte-exact 0–255 binary round-trip through a real
zip/unzip cycle.

**What didn't work (initially)**: the "obvious" implementation of the zip
helper was silently wrong — it passed its own integrity check while
producing corrupted output, because of two independent bugs in js-exec's
`Buffer`/`fs` shim (indexed access, NUL-byte truncation). That's the kind of
failure that's dangerous specifically because it *looks* like success; it
only surfaced once I diffed extracted content against the source files
instead of trusting `unzip -t`.

**What I'd try next**: report the two shim bugs upstream (indexed `Buffer`
access; NUL-byte truncation in `writeFileSync`/`readFileSync(path, enc)`) —
they'd trip up anyone using js-exec for real binary processing, not just
this zip use case. Worth also benchmarking a non-QuickJS path (a
`defineCommand`-based `zip` running as trusted host JS directly against
`ctx.fs`, no worker/WASM boundary) to isolate how much of the ~139x gap is
"QuickJS/WASM" versus "synchronous worker bridge per file read" versus
"interpreted vs. native" — the current benchmark only shows the combined
cost, not the breakdown.

**Can this be made to work as a general-purpose sandboxed-bash-with-a-workspace
system?** Yes, for the bash-execution and filesystem-confinement core —
that part is solid and the security properties I could test held. For
CPU/IO-heavy workloads pushed through `js-exec` specifically, treat it as
genuinely experimental: budget for it being both far slower than native
(expected, that's the isolation tax) and, as found here, capable of failing
silently in ways a naive integrity check won't catch. I'd trust it today for
scripted text/file manipulation over the workspace; I would not yet trust
an unreviewed `js-exec` binary-data pipeline without the kind of
byte-for-byte round-trip test this experiment added.
