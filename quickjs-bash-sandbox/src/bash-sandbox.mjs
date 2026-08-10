import { Bash, ReadWriteFs } from "just-bash";
import { mkdirSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

import { ZIP_BOOTSTRAP } from "./zip-bootstrap.mjs";

/**
 * BashSandbox runs bash scripts through just-bash: a bash parser/interpreter
 * written in JS, not a real shell. There is no fork/exec of `/bin/bash` and
 * no arbitrary native binaries — only the fixed set of commands just-bash
 * implements. Filesystem access is limited to a single real directory on
 * disk (the "workspace") via just-bash's ReadWriteFs, which resolves all
 * paths against that root, so `..` traversal clamps at the workspace
 * boundary instead of escaping it (verified in test/bash-sandbox.test.mjs).
 *
 * With `enableZip` (which implies `javascript: true`), bash scripts can call
 * `js-exec` to run JavaScript inside an actual QuickJS WASM VM (a 64 MB
 * memory limit and its own execution deadline, separate from the bash-level
 * limits below), with a `zipDirectoryToBase64()` helper preloaded. See
 * zip-bootstrap.mjs for why that helper returns base64 over stdout instead
 * of writing the archive itself.
 */
export class BashSandbox {
  /**
   * @param {object} opts
   * @param {string} opts.workspace - Real directory the sandbox may read/write. Created if missing.
   * @param {false|object} [opts.network=false] - Pass a just-bash NetworkConfig (see its README) to enable curl; omit/false to keep network disabled.
   * @param {boolean} [opts.enableZip=false] - Enable js-exec (QuickJS) and preload the zip helper.
   * @param {"normal"|"hardened"} [opts.executionLimitProfile="hardened"]
   * @param {object} [opts.executionLimits] - Overrides merged on top of the profile.
   */
  constructor({
    workspace,
    network = false,
    enableZip = false,
    executionLimitProfile = "hardened",
    executionLimits,
  } = {}) {
    if (!workspace) throw new Error("BashSandbox requires a `workspace` directory");
    this.workspacePath = resolve(workspace);
    mkdirSync(this.workspacePath, { recursive: true });

    this.enableZip = enableZip;
    const fs = new ReadWriteFs({ root: this.workspacePath });

    this.bash = new Bash({
      fs,
      cwd: "/",
      network: network || undefined,
      javascript: enableZip ? { bootstrap: ZIP_BOOTSTRAP } : false,
      executionLimitProfile,
      executionLimits,
    });
  }

  /**
   * Run a bash script against the workspace.
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number, durationMs: number}>}
   */
  async run(script, opts = {}) {
    const start = Date.now();
    const result = await this.bash.exec(script, opts);
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      durationMs: Date.now() - start,
    };
  }

  /** Run a bash script file that already exists inside the workspace (path relative to workspace root). */
  async runFile(relativePath, opts = {}) {
    return this.run(`bash ${JSON.stringify(toSandboxPath(relativePath))}`, opts);
  }

  /**
   * Zip a workspace directory using the QuickJS-sandboxed zip helper.
   * Requires `enableZip: true` at construction time.
   *
   * The archive is assembled entirely inside the QuickJS VM (see
   * zip-bootstrap.mjs), then base64-decoded and written to disk here, in
   * trusted host code — js-exec's fs.writeFileSync() truncates binary
   * writes at the first embedded 0x00 byte, so the sandbox can't safely
   * write the .zip file itself.
   *
   * @param {string} srcDirInWorkspace - Directory inside the workspace, e.g. "input" or "/input".
   * @param {string} destZipInWorkspace - Output .zip path inside the workspace.
   */
  async zipDirectory(srcDirInWorkspace, destZipInWorkspace) {
    if (!this.enableZip) {
      throw new Error("zipDirectory() requires the sandbox to be constructed with enableZip: true");
    }
    const srcDir = toSandboxPath(srcDirInWorkspace);
    const jsCode = `const r = zipDirectoryToBase64(${JSON.stringify(srcDir)}); console.log(r.count); console.log(r.bytes); console.log(r.base64);`;

    const start = Date.now();
    const result = await this.bash.exec("js-exec", { args: ["-c", jsCode] });
    const durationMs = Date.now() - start;

    if (result.exitCode !== 0) {
      throw new Error(`zipDirectory failed (exit ${result.exitCode}): ${result.stderr}`);
    }

    const firstNewline = result.stdout.indexOf("\n");
    const secondNewline = result.stdout.indexOf("\n", firstNewline + 1);
    const count = Number(result.stdout.slice(0, firstNewline));
    const bytes = Number(result.stdout.slice(firstNewline + 1, secondNewline));
    const base64 = result.stdout.slice(secondNewline + 1).trim();
    const buffer = Buffer.from(base64, "base64");

    const destPath = join(this.workspacePath, destZipInWorkspace.replace(/^\/+/, ""));
    writeFileSync(destPath, buffer);

    return { fileCount: count, archiveBytes: bytes, writtenBytes: buffer.length, durationMs, destPath };
  }
}

function toSandboxPath(p) {
  return isAbsolute(p) ? p : "/" + p.replace(/^\/+/, "");
}
