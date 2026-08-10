// Loads the just-bash bundle (dist/bundle/index.js) as real guest code
// inside a QuickJS WASM VM (via quickjs-emscripten), instead of running
// just-bash directly in Node. The whole bash interpreter -- parsing,
// command dispatch, `tar`, text processing, everything -- executes inside
// the WASM sandbox; Node only supplies a module loader for the handful of
// Node builtins the bundle statically imports, small polyfills for
// browser/runtime globals QuickJS doesn't have (TextEncoder, performance,
// timers), and, per BashSandbox, the filesystem bridge to the workspace
// directory (see workspace-fs.mjs).
//
// just-bash's own optional heavy features -- python3 (CPython/WASM),
// js-exec (its own *nested* QuickJS), sqlite3 (sql.js/WASM) -- are never
// enabled here and their command chunks are excluded via the `commands`
// filter, so we never need real WebAssembly instantiation inside our
// QuickJS guest (which QuickJS doesn't support at all).
import { getQuickJS } from "quickjs-emscripten";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

// package.json's "exports" map only publishes "." and "./browser"; resolve
// the bare specifier under the "import" condition (import.meta.resolve, not
// createRequire) so we get dist/bundle/index.js, the ESM build -- the CJS
// build (dist/bundle/index.cjs) doesn't re-export the same named bindings.
const BUNDLE_ENTRY = fileURLToPath(import.meta.resolve("just-bash"));
const BUNDLE_DIR = path.dirname(BUNDLE_ENTRY);
const ENTRY_SPECIFIER = "just-bash-quickjs-entry";

// Everything the bundle imports that isn't a relative `./chunks/...` file.
// Most are stubs that throw if actually *called* -- fine, since nothing we
// exercise (core bash + the command set BashSandbox selects) calls them.
// See README.md for how this list was derived (iteratively, from the
// actual load errors) and why each one is safe to stub.
const NODE_AND_PACKAGE_STUBS = {
  "node:path": `
    export function join(...parts) { return ("/" + parts.filter(Boolean).join("/")).replace(/\\/+/g, "/"); }
    export function resolve(...parts) { return join(...parts); }
    export function dirname(p) { const i = p.lastIndexOf("/"); return i <= 0 ? "/" : p.slice(0, i); }
    export function basename(p, ext) { let b = p.slice(p.lastIndexOf("/") + 1); if (ext && b.endsWith(ext)) b = b.slice(0, -ext.length); return b; }
    export function extname(p) { const b = basename(p); const i = b.lastIndexOf("."); return i <= 0 ? "" : b.slice(i); }
    export function relative(from, to) { return to; }
    export function normalize(p) { return p; }
    export function isAbsolute(p) { return p.startsWith("/"); }
    export const sep = "/";
    export const posix = { join, resolve, dirname, basename, extname, relative, normalize, isAbsolute, sep };
    export const win32 = posix;
    export default { join, resolve, dirname, basename, extname, relative, normalize, isAbsolute, sep, posix, win32 };
  `,
  // Only reached by OverlayFs/ReadWriteFs/the CLI, none of which BashSandbox
  // uses (it supplies its own workspace-scoped fs -- see workspace-fs.mjs).
  "node:fs": stubModule(["realpathSync", "lstatSync", "readlinkSync", "existsSync", "statSync", "readdirSync"], {
    constants: "{ O_RDONLY: 0, O_NOFOLLOW: 0 }",
    promises: `{
      open: __unsupported("promises.open"), mkdir: __unsupported("promises.mkdir"),
      access: __unsupported("promises.access"), lstat: __unsupported("promises.lstat"),
      readdir: __unsupported("promises.readdir"), rm: __unsupported("promises.rm"),
      cp: __unsupported("promises.cp"), realpath: __unsupported("promises.realpath"),
      readlink: __unsupported("promises.readlink"), rename: __unsupported("promises.rename"),
      symlink: __unsupported("promises.symlink"), link: __unsupported("promises.link"),
    }`,
  }),
  "node:fs/promises": stubModule(["open", "mkdir", "access", "lstat", "readdir", "rm", "cp", "realpath", "readlink", "rename", "symlink", "link"]),
  "node:dns": stubModule(["lookup"]),
  "node:worker_threads": stubModule(["Worker", "parentPort", "workerData", "isMainThread"]),
  "node:zlib": stubModule(["gzipSync", "gunzipSync", "constants"]),
  "node:crypto": stubModule(["createHash", "randomUUID"]),
  "node:url": `
    export function fileURLToPath(u) { return String(u).replace(/^file:\\/\\//, ""); }
    export function pathToFileURL(p) { return { href: "file://" + p, toString: () => "file://" + p }; }
    export default { fileURLToPath, pathToFileURL };
  `,
  "node:module": `
    export function createRequire() { return () => { throw new Error("require() not supported in this sandbox"); }; }
    export default { createRequire };
  `,
  "node:async_hooks": `
    export class AsyncLocalStorage {
      run(store, fn, ...args) { const prev = this._store; this._store = store; try { return fn(...args); } finally { this._store = prev; } }
      getStore() { return this._store; }
    }
    export default { AsyncLocalStorage };
  `,
  // Optional third-party deps only reached by commands BashSandbox excludes
  // by default (bzip2 tar entries, sqlite3, html-to-markdown). Stubbed so
  // the *module graph* still loads (these are static imports of shared
  // chunks) even though the features themselves are unavailable.
  "seek-bzip": `export default function Bzip2() { throw new Error("bzip2 (tar -j) is not supported in this sandbox"); }`,
  "sql.js": `export default function initSqlJs() { throw new Error("sqlite3 is not supported in this sandbox (requires WebAssembly)"); }`,
  "turndown": `export default class TurndownService { constructor() { throw new Error("html-to-markdown is not supported in this sandbox"); } }`,
};

function stubModule(namedExports, extra = {}) {
  const lines = [`function __unsupported(name) { return (...args) => { throw new Error("not supported in this sandbox: " + name); }; }`];
  for (const name of namedExports) lines.push(`export const ${name} = __unsupported(${JSON.stringify(name)});`);
  const extraKeys = Object.keys(extra);
  for (const key of extraKeys) lines.push(`export const ${key} = ${extra[key]};`);
  lines.push(`export default { ${[...namedExports, ...extraKeys].join(", ")} };`);
  return lines.join("\n");
}

// Minimal polyfills for globals QuickJS doesn't provide but the bundle
// references at module scope or during normal (non-WASM) execution.
const GLOBALS_POLYFILL = `
  globalThis.TextEncoder = class TextEncoder {
    encode(str) {
      str = String(str);
      const bytes = [];
      for (let i = 0; i < str.length; i++) {
        let cp = str.codePointAt(i);
        if (cp > 0xffff) i++;
        if (cp < 0x80) bytes.push(cp);
        else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
        else if (cp < 0x10000) bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
        else bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      }
      return new Uint8Array(bytes);
    }
    encodeInto(str, dest) {
      const bytes = this.encode(str);
      const written = Math.min(bytes.length, dest.length);
      dest.set(bytes.subarray(0, written));
      return { read: str.length, written };
    }
  };
  globalThis.TextDecoder = class TextDecoder {
    constructor(enc) { this.encoding = enc || "utf-8"; }
    decode(bytes) {
      if (!bytes) return "";
      let out = "", i = 0;
      while (i < bytes.length) {
        let b0 = bytes[i++], cp, extra;
        if (b0 < 0x80) { cp = b0; extra = 0; }
        else if ((b0 & 0xe0) === 0xc0) { cp = b0 & 0x1f; extra = 1; }
        else if ((b0 & 0xf0) === 0xe0) { cp = b0 & 0x0f; extra = 2; }
        else if ((b0 & 0xf8) === 0xf0) { cp = b0 & 0x07; extra = 3; }
        else { cp = 0xfffd; extra = 0; }
        for (let k = 0; k < extra; k++) cp = (cp << 6) | (bytes[i++] & 0x3f);
        if (cp > 0xffff) { cp -= 0x10000; out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff)); }
        else out += String.fromCharCode(cp);
      }
      return out;
    }
  };
  globalThis.performance = { now: () => Date.now() };
  globalThis.console = {
    log: (...args) => globalThis.__host_console_log(args.map(String).join(" ")),
    info: (...args) => globalThis.__host_console_log(args.map(String).join(" ")),
    warn: (...args) => globalThis.__host_console_log(args.map(String).join(" ")),
    error: (...args) => globalThis.__host_console_log(args.map(String).join(" ")),
    debug: (...args) => globalThis.__host_console_log(args.map(String).join(" ")),
  };
  // Minimal Web Streams polyfill (no backpressure/queuing strategy) --
  // enough for just-bash's \`tar\` command, which produces entries
  // synchronously into a ReadableStream and drains a WritableStream the
  // same way. Real async I/O never crosses this boundary in this sandbox.
  globalThis.ReadableStream = class ReadableStream {
    constructor(underlyingSource = {}) {
      this._queue = [];
      this._closed = false;
      this._errored = undefined;
      this._pendingResolve = null;
      this._pendingReject = null;
      const controller = {
        enqueue: (chunk) => {
          if (this._pendingResolve) {
            const resolve = this._pendingResolve;
            this._pendingResolve = this._pendingReject = null;
            resolve({ value: chunk, done: false });
          } else {
            this._queue.push(chunk);
          }
        },
        close: () => {
          this._closed = true;
          if (this._pendingResolve) {
            const resolve = this._pendingResolve;
            this._pendingResolve = this._pendingReject = null;
            resolve({ value: undefined, done: true });
          }
        },
        error: (e) => {
          this._errored = e;
          if (this._pendingReject) {
            const reject = this._pendingReject;
            this._pendingResolve = this._pendingReject = null;
            reject(e);
          }
        },
      };
      if (underlyingSource.start) underlyingSource.start(controller);
    }
    getReader() {
      return {
        read: () => {
          if (this._queue.length) return Promise.resolve({ value: this._queue.shift(), done: false });
          if (this._errored !== undefined) return Promise.reject(this._errored);
          if (this._closed) return Promise.resolve({ value: undefined, done: true });
          return new Promise((resolve, reject) => { this._pendingResolve = resolve; this._pendingReject = reject; });
        },
        releaseLock() {},
        cancel: () => Promise.resolve(),
      };
    }
  };
  globalThis.Blob = class Blob {
    constructor(parts = [], options = {}) {
      let total = 0;
      const bufs = parts.map((p) => {
        const bytes = p instanceof Uint8Array ? p : typeof p === "string" ? new TextEncoder().encode(p) : new Uint8Array(p);
        total += bytes.length;
        return bytes;
      });
      const merged = new Uint8Array(total);
      let offset = 0;
      for (const b of bufs) { merged.set(b, offset); offset += b.length; }
      this._bytes = merged;
      this.size = merged.length;
      this.type = options.type || "";
    }
    slice(start, end, type) {
      const b = new Blob([this._bytes.slice(start, end)]);
      if (type) b.type = type;
      return b;
    }
    async arrayBuffer() { return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength); }
    async text() { return new TextDecoder().decode(this._bytes); }
    stream() {
      const bytes = this._bytes;
      return new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } });
    }
  };
  globalThis.WritableStream = class WritableStream {
    constructor(underlyingSink = {}) { this._sink = underlyingSink; }
    getWriter() {
      return {
        write: (chunk) => Promise.resolve(this._sink.write && this._sink.write(chunk)),
        close: () => Promise.resolve(this._sink.close && this._sink.close()),
        abort: (e) => Promise.resolve(this._sink.abort && this._sink.abort(e)),
        releaseLock() {},
      };
    }
    // Spec convenience methods -- WritableStream.prototype.close()/abort()
    // work without a writer, equivalent to getWriter().close()/.abort().
    // modern-tar (tar's archive engine) relies on this for empty-body entries.
    close() { return this.getWriter().close(); }
    abort(reason) { return this.getWriter().abort(reason); }
  };
  globalThis.setTimeout = (fn, ms, ...args) => globalThis.__host_setTimeout(() => fn(...args), ms || 0);
  globalThis.clearTimeout = (id) => globalThis.__host_clearTimeout(id);
  globalThis.setInterval = () => { throw new Error("setInterval not supported in this sandbox"); };
  globalThis.clearInterval = () => {};
  globalThis.queueMicrotask = (fn) => Promise.resolve().then(fn);
`;

function evalOrThrow(context, code, filename, opts) {
  const result = context.evalCode(code, filename, opts);
  if (result.error) {
    const dumped = context.dump(result.error);
    result.error.dispose();
    const err = new Error(`QuickJS error in ${filename}: ${dumped && dumped.message ? dumped.message : JSON.stringify(dumped)}`);
    err.quickjsDetail = dumped;
    throw err;
  }
  return result.value;
}

/**
 * Creates a fresh QuickJS runtime/context with the just-bash bundle loaded
 * as guest code and `globalThis.Bash` set. Real host timers are wired up
 * (see below) because just-bash races command execution against a
 * `setTimeout(..., maxExecutionTimeMs)` watchdog for deadline enforcement.
 */
export async function createJustBashQuickJSRuntime() {
  const QuickJS = await getQuickJS();
  const runtime = QuickJS.newRuntime();
  const context = runtime.newContext();

  runtime.setModuleLoader(
    (moduleName) => {
      if (Object.prototype.hasOwnProperty.call(NODE_AND_PACKAGE_STUBS, moduleName)) {
        return NODE_AND_PACKAGE_STUBS[moduleName];
      }
      if (moduleName === ENTRY_SPECIFIER) {
        return `
          import { Bash, InMemoryFs, defineCommand } from ${JSON.stringify(BUNDLE_ENTRY)};
          globalThis.Bash = Bash;
          globalThis.InMemoryFs = InMemoryFs;
          globalThis.defineCommand = defineCommand;
        `;
      }
      try {
        return readFileSync(moduleName, "utf8");
      } catch (e) {
        return { error: new Error(`cannot load module '${moduleName}': ${e.message}`) };
      }
    },
    (baseName, requestedName) => {
      if (Object.prototype.hasOwnProperty.call(NODE_AND_PACKAGE_STUBS, requestedName)) return requestedName;
      if (requestedName.startsWith("node:") || requestedName === ENTRY_SPECIFIER) return requestedName;
      if (requestedName.startsWith(".") || requestedName.startsWith("/")) {
        const baseDir = baseName === ENTRY_SPECIFIER || baseName.startsWith("node:") ? BUNDLE_DIR : path.dirname(baseName);
        return path.resolve(baseDir, requestedName);
      }
      // Bare package specifier without its own stub (e.g. minimatch, needed
      // by `ls`/`find` glob matching): resolve it for real through Node's
      // own module resolution -- these are genuine pure-JS dependencies
      // that just work as guest code, unlike the WASM/Node-native ones
      // that got stubbed above.
      try {
        return fileURLToPath(import.meta.resolve(requestedName, "file://" + BUNDLE_ENTRY));
      } catch (e) {
        return requestedName; // let the loader report a clear "cannot load" error
      }
    }
  );

  // Real host-driven timers: see GLOBALS_POLYFILL's setTimeout/clearTimeout.
  // A fake "resolve on next microtask, ignore the delay" stub makes every
  // just-bash command look like it exceeded its execution deadline
  // instantly, because just-bash's deadline enforcement is itself a
  // `Promise.race` against a `setTimeout(reject, maxExecutionTimeMs)`.
  const pendingTimers = new Map();
  let nextTimerId = 1;
  context
    .newFunction("__host_setTimeout", (fnHandle, msHandle) => {
      const ms = context.getNumber(msHandle);
      const id = nextTimerId++;
      const dupedFn = fnHandle.dup();
      const nodeHandle = setTimeout(() => {
        pendingTimers.delete(id);
        const callResult = context.callFunction(dupedFn, context.undefined);
        dupedFn.dispose();
        if (callResult.error) {
          callResult.error.dispose();
        } else {
          callResult.value.dispose();
        }
        runtime.executePendingJobs(-1);
      }, ms);
      nodeHandle.unref?.();
      pendingTimers.set(id, { nodeHandle, guestFnHandle: dupedFn });
      return context.newNumber(id);
    })
    .consume((h) => context.setProp(context.global, "__host_setTimeout", h));
  context
    .newFunction("__host_clearTimeout", (idHandle) => {
      const id = context.getNumber(idHandle);
      const entry = pendingTimers.get(id);
      if (entry) {
        clearTimeout(entry.nodeHandle);
        entry.guestFnHandle.dispose();
        pendingTimers.delete(id);
      }
    })
    .consume((h) => context.setProp(context.global, "__host_clearTimeout", h));
  context
    .newFunction("__host_console_log", (msgHandle) => {
      // Not the shell's stdout/stderr (that's BashSandbox.run()'s return
      // value) -- just a sink for guest code (e.g. the `file` command) that
      // expects a global `console` to exist, kept off the real console by
      // default so it can't be used to smuggle output past exec()'s result.
    })
    .consume((h) => context.setProp(context.global, "__host_console_log", h));

  evalOrThrow(context, GLOBALS_POLYFILL, "globals-polyfill.js", { type: "global" }).dispose();
  evalOrThrow(context, `import ${JSON.stringify(ENTRY_SPECIFIER)};`, "entry.js", { type: "module" }).dispose();
  runtime.executePendingJobs(-1);

  /** Pumps the QuickJS job queue with real waits so host timers can fire, until `doneGlobal` is truthy. */
  async function pumpUntil(doneGlobal, { pollMs = 5, maxWaitMs = 60_000 } = {}) {
    const deadline = Date.now() + maxWaitMs;
    for (;;) {
      runtime.executePendingJobs(-1);
      const doneHandle = evalOrThrow(context, doneGlobal, "poll.js", { type: "global" });
      const done = context.dump(doneHandle);
      doneHandle.dispose();
      if (done) return;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${doneGlobal}`);
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }

  function dispose() {
    for (const { nodeHandle, guestFnHandle } of pendingTimers.values()) {
      clearTimeout(nodeHandle);
      guestFnHandle.dispose();
    }
    pendingTimers.clear();
    context.dispose();
    try {
      runtime.dispose();
    } catch (e) {
      // Known limitation, reproducible past ~700KB-1MB of data processed by
      // commands that build up JS reference cycles on the guest side (`tar`
      // via its own stream-based archive writer, in testing here) --
      // QuickJS is reference-counted with a separate, only-manually-invoked
      // cycle collector, quickjs-emscripten's sync build exposes no way to
      // trigger it, and `JS_FreeRuntime` asserts the object list is empty
      // rather than collecting cycles itself. The operation's *result* is
      // already produced and correct by this point (see the tar benchmark
      // and tests) -- only this WASM instance's own teardown fails. Safe to
      // swallow for short-lived processes/scripts; a long-running server
      // creating many BashSandbox instances should treat this as a real
      // per-instance memory leak and prefer a worker/process pool that gets
      // recycled, rather than assuming dispose() reliably frees memory.
      console.warn(`quickjs-bash-sandbox: QuickJS runtime disposal failed (known limitation, see quickjs-runtime.mjs): ${e.message || e}`);
    }
  }

  return { context, runtime, evalOrThrow, pumpUntil, dispose };
}
