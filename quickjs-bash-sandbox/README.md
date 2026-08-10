# quickjs-bash-sandbox

The [`just-bash`](https://github.com/vercel-labs/just-bash) bash interpreter
— parsing, command dispatch, `tar`, everything — running as guest code
inside a real [QuickJS](https://bellard.org/quickjs/) WASM VM
(`quickjs-emscripten`), not in Node's own V8. Filesystem access is confined
to one real directory on disk (the "workspace") through a synchronous
host/guest bridge.

```js
import { BashSandbox } from "./src/bash-sandbox.mjs";

const sandbox = await BashSandbox.create({ workspace: "/path/to/workspace" });
const result = await sandbox.run('echo "hello" > greeting.txt && cat greeting.txt');
// { stdout: "hello\n", stderr: "", exitCode: 0, durationMs: 12 }
sandbox.dispose();
```

That's the API for the common case: one class, one `workspace` directory,
`run(script)` in, `{ stdout, stderr, exitCode, durationMs }` out. Files the
script writes land on real disk under `workspace`; files already there are
visible to the script.

## Why this exists / what changed from the first version

The original version of this experiment ran `just-bash` normally in Node
and only used QuickJS for its optional `js-exec` feature (embedded
JavaScript snippets). That's a real, useful design, but it isn't "just-bash
inside QuickJS" — the bash interpreter itself was running in Node's V8 the
whole time. This version does the thing literally: the ~500 KB just-bash
bundle is loaded and evaluated *as guest code* inside a QuickJS context, so
the interpreter, the parser, and every built-in command execute inside the
WASM sandbox. See `git log` for that earlier version if you want to compare.

## Architecture

```
Node.js host process
  └─ BashSandbox (src/bash-sandbox.mjs)
       └─ QuickJS WASM VM (src/quickjs-runtime.mjs)
            └─ just-bash's dist/bundle/index.js, evaluated as an ES module
                 ├─ parses and interprets the bash script
                 ├─ dispatches to built-in commands (tar, ls, grep, sed, ...)
                 └─ fs calls → WorkspaceFs (src/workspace-fs.mjs, guest-side)
                      └─ synchronous __wfs_* host bridge functions
                           └─ real node:fs, scoped + clamped to the workspace root
```

There is no `fork`/`exec` of `/bin/bash` anywhere, and no arbitrary native
binaries — only the fixed set of commands just-bash implements, running as
interpreted bytecode inside a WASM sandbox with its own memory space,
separate from Node's own heap. Filesystem access goes through a bridge that
resolves every path against the workspace root with `..` traversal clamped
at that root, on both the guest side (path arithmetic) and the host side
(the actual `node:fs` calls) — confirmed in `test/bash-sandbox.test.mjs` to
stay inside the workspace rather than reaching the real filesystem outside
it.

## Making the bundle load inside QuickJS

just-bash's own bundle is written for Node: it does `import ... from
"node:fs"`, spawns `worker_threads.Worker`s for its `js-exec`/`python3`/
`sqlite3` features, and expects a handful of runtime globals (`TextEncoder`,
`ReadableStream`, `Blob`, `setTimeout`, ...) that QuickJS doesn't provide.
`src/quickjs-runtime.mjs` makes it loadable by:

- **A module loader** (`runtime.setModuleLoader`) that serves small stub
  modules for `node:fs`, `node:path`, `node:dns`, `node:module`,
  `node:worker_threads`, `node:zlib`, `node:crypto`, `node:url`,
  `node:async_hooks`, and the handful of third-party deps that don't apply
  here (`sql.js`, `seek-bzip`, `turndown`) — all of just-bash's optional
  heavy features (`python3`, `js-exec`, `sqlite3`, gzip/bzip2 compression)
  are excluded via the command allowlist (`BashSandbox.DEFAULT_COMMANDS`),
  so these stubs only need to exist for the module graph to resolve; they're
  never actually called. Everything else — real dependencies like
  `minimatch` (glob matching, used by `ls`/`find`) and `diff` — resolves for
  real through Node's own module resolution, because they're genuine
  pure-JS code with no Node-specific APIs and just work as guest code.
- **Small polyfills** for `TextEncoder`/`TextDecoder` (including
  `encodeInto`, which the `modern-tar` package — just-bash's tar engine —
  calls directly), `performance.now()`, a minimal `console`, and a
  best-effort `ReadableStream`/`WritableStream`/`Blob` (no backpressure —
  everything here is synchronous host I/O under the hood, so it doesn't
  need any).
- **Real host-driven timers.** just-bash enforces its execution-time limits
  with a `Promise.race` against `setTimeout(reject, maxExecutionTimeMs)`. A
  naive "resolve on the next microtask, ignore the delay" `setTimeout` stub
  makes *every* command look like it instantly exceeded its deadline. The
  guest's `setTimeout`/`clearTimeout` are bridged to genuine Node timers
  (`context.newFunction` calling real `setTimeout`, then calling back into
  the guest via `context.callFunction` when it actually fires).

Two real bugs surfaced while getting `tar` to work, both found by testing,
neither documented anywhere:

- The polyfilled `TextEncoder` initially had no `encodeInto()` — only
  `encode()`. `modern-tar`'s header-writing code calls `encodeInto()`
  directly, and its `try`/`catch` around header construction *swallows* the
  resulting `TypeError` and reports a misleading, unrelated error
  ("No active tar entry.") from a completely different call site. Tracing
  it required cloning `modern-tar`'s unminified source to find the real
  call site — the bundled/minified error message was actively misleading.
- The polyfilled `WritableStream` only exposed `close()`/`abort()` through
  `getWriter()`. The WHATWG spec (and `modern-tar`) also calls
  `stream.close()` directly for zero-byte entries (directories); without
  that convenience method it fails with "not a function".

## API

```ts
BashSandbox.create({
  workspace: string,          // required: real directory, created if missing
  commands?: string[],        // just-bash command names to register; default: DEFAULT_COMMANDS
  executionLimitProfile?: "normal" | "hardened", // default: "hardened"
  executionLimits?: object,   // see just-bash README, e.g. maxExecutionTimeMs
}) → Promise<BashSandbox>

sandbox.run(script, opts?)              // -> { stdout, stderr, exitCode, durationMs }
sandbox.runFile(relativePath, opts?)
sandbox.tarDirectory(srcDir, destTar)   // just-bash's own `tar`, see below
sandbox.dispose()
```

Construction is async (it loads and evaluates the bundle into a fresh
QuickJS context, ~230ms), so use the static `create()` factory rather than
`new`. `run()`/`runFile()` accept the same per-call options as just-bash's
own `exec()` (`env`, `cwd`, `stdin`, etc.).

`DEFAULT_COMMANDS` covers core navigation, file operations, and text
processing (`ls`, `cat`, `grep`, `sed`, `awk`, `find`, ...) plus `tar`. It
excludes `sqlite3`/`gzip`/`gunzip`/`zcat`/`yq`/`xan`/`jq`/`html-to-markdown`
(dependencies not vetted for this sandbox) and `printf` (needs `sprintf-js`,
which ships as a UMD script rather than an ES module — fixable with a small
polyfill, not done here). `python3`, `js-exec`, and network (`curl`) are
just-bash features that are off unless separately opted into, and this
sandbox never opts in — see `src/quickjs-runtime.mjs` for exactly what's
stubbed and why each stub is safe.

## `tarDirectory()`

```js
const result = await sandbox.tarDirectory("input", "archive.tar");
// { stdout: "", stderr: "", exitCode: 0, durationMs: 331 }
```

This just runs `tar -cf <dest> -C <src> .` through `sandbox.run()` — no
special-casing, no workaround. Unlike the earlier `js-exec`-based zip
approach (which had to route the finished archive out through
base64-encoded `stdout` because of NUL-byte-truncation bugs in js-exec's own
`Buffer`/`fs` shim — see the previous version of this file if you're
curious), the file is written directly by the sandboxed `tar` command
through the same workspace fs bridge every other command uses. A 256-byte
file covering every byte value including embedded `0x00` round-trips
correctly through a real tar/untar cycle — see the test suite.

### Benchmark: 1000 files x 2 KiB, tar vs. native `tar`

| Method | Median |
|---|---|
| `BashSandbox.tarDirectory` (whole interpreter in QuickJS) | 331 ms |
| native `tar` | 12 ms |

**~28x slower than native `tar`** — down from ~139x in the earlier
`js-exec`-based zip version, because running the whole interpreter (and
`tar`'s own archive writer) inside QuickJS, talking to the filesystem
through a same-thread synchronous bridge, is architecturally cheaper than
routing every file read through `js-exec`'s worker-thread/`Atomics.wait`
boundary. Full numbers and discussion:
[`results/tar-benchmark-results.md`](results/tar-benchmark-results.md).
Reproduce with `npm run benchmark`.

## Known limitation: QuickJS runtime teardown can fail past ~1 MB of processed data

Once total data flowing through a `tar` operation crosses roughly 700 KB–1
MB in one `run()`/`tarDirectory()` call, `sandbox.dispose()` can hit a
QuickJS-internal assertion (`list_empty(&rt->gc_obj_list)` in
`JS_FreeRuntime`). QuickJS is reference-counted with a separate cycle
collector that has to be invoked explicitly to reclaim reference cycles
(plausibly created by the stream polyfill's closures); `quickjs-emscripten`'s
synchronous build exposes no way to trigger that collector, and
`JS_FreeRuntime` asserts instead of collecting cycles itself on the way out.

The *operation's result is already correct and on disk* by the time this
happens — confirmed by the benchmark and by
`test/bash-sandbox.test.mjs`'s "hit the known QuickJS teardown limitation"
test — only the WASM instance's own teardown fails. `dispose()` catches and
logs it rather than throwing, so it's safe for short-lived scripts. A
long-running server creating many `BashSandbox` instances should treat this
as a real per-instance memory leak, not something `dispose()` reliably
prevents, and prefer a recycled worker/process pool over holding sandboxes
open indefinitely.

## Running

```bash
npm install
npm test         # 14 tests: exec semantics, workspace confinement,
                  # execution limits, tar correctness, teardown limitation
npm run benchmark
```

## Honest assessment

**What worked**: the core ask — running the *actual* just-bash interpreter,
not just embedded JavaScript, inside a real QuickJS WASM VM, scoped to one
real workspace directory via a synchronous host bridge — works, including
`tar` (no custom archiver needed; just-bash's own command works once the
bundle loads). Security properties held under the same adversarial tests as
before (path traversal, absolute-path escapes, no network by default,
execution-time limits actually enforced via real host timers). All 14 tests
pass, including a byte-exact 0–255 binary round-trip through a real
tar/untar cycle, and the benchmark is a meaningful ~5x improvement over the
previous architecture's overhead (28x vs. 139x slower than native).

**What didn't work (initially)**: getting the vendor bundle to load and run
at all took real iteration — nine or so missing globals/module stubs found
one `evalCode` error at a time, then two genuine bugs in `modern-tar`
(missing `TextEncoder.encodeInto`, missing `WritableStream.close()`) that
manifested as *misleading, unrelated* error messages ("No active tar
entry.", "not a function") because of bare `catch {}` blocks in the vendor
code swallowing the real cause. Neither was discoverable by reading the
error message alone; both needed cloning the library's actual source to
find the real call site. Separately, the QuickJS teardown assertion at
scale is a genuine, currently-unworked-around limitation, not just a
benchmark curiosity — anything using this sandbox for real needs to budget
for it explicitly rather than assume `dispose()` is reliable.

**What I'd try next**: implement the sprintf-js polyfill to restore
`printf`; find or implement a way to force QuickJS's cycle collector before
`JS_FreeRuntime` (or confirm none exists in `quickjs-emscripten`'s public
API and report it upstream); and profile how much of the 28x is guest-side
bytecode interpretation vs. the fs-bridge round-trip per file, to know which
one is worth optimizing further.

**Can this be made to work as a general-purpose sandboxed-bash system?**
Yes, and more convincingly than the earlier `js-exec`-based version — this
is the architecture that actually matches "bash running inside QuickJS," it
measurably outperforms the alternative, and its security properties held up
under testing. The teardown limitation is real and needs a mitigation
strategy (process/worker recycling) for any long-running use, not just a
caught warning; I'd treat that as the one blocking item before trusting this
in production rather than as an experiment.
