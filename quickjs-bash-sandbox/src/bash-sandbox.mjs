import { resolve as resolveHostPath, isAbsolute } from "node:path";

import { createJustBashQuickJSRuntime } from "./quickjs-runtime.mjs";
import { installWorkspaceFs } from "./workspace-fs.mjs";

// Commands enabled by default: core navigation/file/text-processing plus
// `tar`. Deliberately excludes:
//   - sqlite3 (needs sql.js/WASM), gzip/gunzip/zcat (needs node:zlib,
//     stubbed as unsupported here), yq/xan/jq/html-to-markdown (pull in
//     dependencies not vetted for this sandbox)
//   - printf (needs `sprintf-js`, which ships as a UMD script rather than
//     an ES module -- it can be located on disk but doesn't parse as guest
//     code; fixable with a small sprintf polyfill, not done here)
// See quickjs-runtime.mjs for exactly which imports are stubbed and why.
// `tar` itself only needs plain (uncompressed, non-bzip2) archives to work;
// `-j` (bzip2) will fail because `seek-bzip` is stubbed the same way.
export const DEFAULT_COMMANDS = [
  "echo", "cat", "ls", "mkdir", "rmdir", "touch", "rm", "cp", "mv", "ln", "chmod",
  "pwd", "readlink", "head", "tail", "wc", "stat", "grep", "fgrep", "egrep", "rg", "sed", "awk",
  "sort", "uniq", "comm", "cut", "paste", "tr", "rev", "nl", "fold", "expand", "unexpand",
  "strings", "split", "column", "join", "tee", "find", "basename", "dirname", "tree", "du",
  "env", "printenv", "alias", "unalias", "history", "xargs", "true", "false", "clear", "bash",
  "sh", "base64", "diff", "date", "sleep", "timeout", "seq", "expr", "file", "help", "which",
  "tac", "hostname", "od", "tar", "time", "whoami",
];

/**
 * BashSandbox runs bash scripts with the *entire* just-bash interpreter --
 * parsing, command dispatch, `tar`, everything -- executing as guest code
 * inside a real QuickJS WASM VM (via quickjs-emscripten), not in the host's
 * V8. See src/quickjs-runtime.mjs for how the bundle is loaded into the
 * guest and src/workspace-fs.mjs for how the guest's filesystem is bridged
 * to one real directory on disk (the "workspace"), with `..` traversal
 * clamped at that root on both sides of the bridge.
 *
 * Construction is async (it loads and evaluates ~500 KB of guest code), so
 * use the static `create()` factory instead of `new`.
 */
export class BashSandbox {
  /**
   * @param {object} opts
   * @param {string} opts.workspace - Real directory the sandbox may read/write. Created if missing.
   * @param {string[]} [opts.commands=DEFAULT_COMMANDS] - just-bash command names to register.
   * @param {"normal"|"hardened"} [opts.executionLimitProfile="hardened"]
   * @param {object} [opts.executionLimits] - Overrides merged on top of the profile.
   */
  static async create({ workspace, commands = DEFAULT_COMMANDS, executionLimitProfile = "hardened", executionLimits = {} } = {}) {
    if (!workspace) throw new Error("BashSandbox.create requires a `workspace` directory");
    const workspacePath = resolveHostPath(workspace);
    const vm = await createJustBashQuickJSRuntime();
    installWorkspaceFs(vm, workspacePath);

    const initCode = `
      globalThis.__bash = new Bash({
        fs: new globalThis.WorkspaceFs(),
        cwd: "/",
        commands: ${JSON.stringify(commands)},
        defenseInDepth: { enabled: false }, // redundant here: the whole interpreter already runs inside a separate QuickJS realm
        executionLimitProfile: ${JSON.stringify(executionLimitProfile)},
        executionLimits: ${JSON.stringify(executionLimits)},
      });
    `;
    vm.evalOrThrow(vm.context, initCode, "init-bash.js", { type: "global" }).dispose();

    return new BashSandbox(vm, workspacePath);
  }

  constructor(vm, workspacePath) {
    this.vm = vm;
    this.workspacePath = workspacePath;
    this._runCounter = 0;
  }

  /**
   * Run a bash script against the workspace, entirely inside the QuickJS guest.
   * @param {string} script
   * @param {{env?: object, cwd?: string, stdin?: string, replaceEnv?: boolean}} [opts]
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number, durationMs: number}>}
   */
  async run(script, opts = {}) {
    const { context, evalOrThrow, pumpUntil } = this.vm;
    const runId = `__run${this._runCounter++}`;
    const code = `
      globalThis.${runId}_done = false;
      (async () => {
        try {
          const r = await globalThis.__bash.exec(${JSON.stringify(script)}, ${JSON.stringify(opts)});
          globalThis.${runId}_result = { stdout: r.stdout, stderr: r.stderr, exitCode: r.exitCode };
        } catch (e) {
          globalThis.${runId}_result = { stdout: "", stderr: String((e && e.stack) || e), exitCode: 1 };
        } finally {
          globalThis.${runId}_done = true;
        }
      })();
    `;
    const start = Date.now();
    evalOrThrow(context, code, `${runId}.js`, { type: "global" }).dispose();
    await pumpUntil(`globalThis.${runId}_done`);
    const durationMs = Date.now() - start;

    const resultHandle = evalOrThrow(context, `globalThis.${runId}_result`, "result.js", { type: "global" });
    const result = context.dump(resultHandle);
    resultHandle.dispose();
    evalOrThrow(context, `delete globalThis.${runId}_done; delete globalThis.${runId}_result;`, "cleanup.js", { type: "global" }).dispose();

    return { ...result, durationMs };
  }

  /** Run a bash script file that already exists inside the workspace (path relative to workspace root). */
  async runFile(relativePath, opts = {}) {
    return this.run(`bash ${shellQuote(toSandboxPath(relativePath))}`, opts);
  }

  /**
   * Tar a workspace directory using just-bash's own `tar` command -- running
   * inside the same QuickJS sandbox as everything else, no special-casing.
   * @param {string} srcDirInWorkspace
   * @param {string} destTarInWorkspace
   */
  async tarDirectory(srcDirInWorkspace, destTarInWorkspace) {
    const src = toSandboxPath(srcDirInWorkspace);
    const dest = toSandboxPath(destTarInWorkspace);
    const result = await this.run(`tar -cf ${shellQuote(dest)} -C ${shellQuote(src)} .`);
    if (result.exitCode !== 0) {
      throw new Error(`tarDirectory failed (exit ${result.exitCode}): ${result.stderr}`);
    }
    return result;
  }

  dispose() {
    this.vm.dispose();
  }
}

function toSandboxPath(p) {
  return isAbsolute(p) ? p : "/" + p.replace(/^\/+/, "");
}

function shellQuote(s) {
  return "'" + String(s).replace(/'/g, `'\\''`) + "'";
}
