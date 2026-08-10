import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { BashSandbox } from "../src/bash-sandbox.mjs";

let workDirs = [];
let sandboxes = [];

function freshWorkspace() {
  const dir = mkdtempSync(join(tmpdir(), "quickjs-bash-sandbox-test-"));
  workDirs.push(dir);
  return dir;
}

async function freshSandbox(opts = {}) {
  const sandbox = await BashSandbox.create({ workspace: freshWorkspace(), ...opts });
  sandboxes.push(sandbox);
  return sandbox;
}

after(() => {
  for (const sandbox of sandboxes) sandbox.dispose();
  for (const dir of workDirs) rmSync(dir, { recursive: true, force: true });
});

// --- basic execution: the whole interpreter runs as guest code inside QuickJS ---

test("runs a simple script inside the QuickJS guest and captures stdout/exitCode", async () => {
  const sandbox = await freshSandbox();
  const r = await sandbox.run('echo "hello from quickjs"');
  assert.equal(r.stdout, "hello from quickjs\n");
  assert.equal(r.exitCode, 0);
  assert.equal(typeof r.durationMs, "number");
});

test("nonzero exit code and stderr are surfaced, not thrown", async () => {
  const sandbox = await freshSandbox();
  const r = await sandbox.run("cat /no/such/file");
  assert.notEqual(r.exitCode, 0);
  assert.match(r.stderr, /no such file|not found/i);
});

test("pipes, redirection, and variables work", async () => {
  const sandbox = await freshSandbox();
  const r = await sandbox.run('X=42; echo "value=$X" | tr a-z A-Z > out.txt; cat out.txt');
  assert.equal(r.stdout, "VALUE=42\n");
});

// --- workspace read/write, mediated entirely by the host fs bridge ---

test("files written by the sandbox land in the real workspace directory", async () => {
  const sandbox = await freshSandbox();
  await sandbox.run('echo "persisted" > note.txt');
  const onDisk = readFileSync(join(sandbox.workspacePath, "note.txt"), "utf8");
  assert.equal(onDisk, "persisted\n");
});

test("filesystem changes persist across separate run() calls, env does not", async () => {
  const sandbox = await freshSandbox();
  await sandbox.run("echo persisted-content > shared.txt; export CARRY=yes");
  const r = await sandbox.run('cat shared.txt; echo "CARRY=${CARRY:-unset}"');
  assert.equal(r.stdout, "persisted-content\nCARRY=unset\n");
});

test("pre-existing files on disk are visible to the sandbox", async () => {
  const sandbox = await freshSandbox();
  writeFileSync(join(sandbox.workspacePath, "seed.txt"), "seeded\n");
  const r = await sandbox.run("cat seed.txt");
  assert.equal(r.stdout, "seeded\n");
});

// --- security: workspace confinement, enforced by the fs bridge (host + guest) ---

test("'..' traversal clamps at the workspace root instead of escaping it", async () => {
  const sandbox = await freshSandbox();
  const r = await sandbox.run("mkdir -p sub && cd sub && echo escaped > ../../../../outside.txt; echo exit=$?");
  assert.match(r.stdout, /exit=0/);
  assert.equal(existsSync(join(sandbox.workspacePath, "..", "outside.txt")), false);
  assert.equal(existsSync(join(tmpdir(), "outside.txt")), false);
  assert.equal(existsSync(join(sandbox.workspacePath, "outside.txt")), true);
});

test("absolute paths outside the workspace are not visible", async () => {
  const sandbox = await freshSandbox();
  const r = await sandbox.run("cat /etc/passwd");
  assert.notEqual(r.exitCode, 0);
  assert.doesNotMatch(r.stdout, /root:/);
});

test("network is disabled by default (curl is not a registered command)", async () => {
  const sandbox = await freshSandbox();
  const r = await sandbox.run("curl --version");
  assert.notEqual(r.exitCode, 0);
  assert.match(r.stderr, /not found/i);
});

// --- resource limits (enforced by the guest interpreter, backed by real host timers) ---

test("runaway loops are stopped by execution limits, not left to hang", async () => {
  const sandbox = await freshSandbox({ executionLimits: { maxExecutionTimeMs: 2_000 } });
  const r = await sandbox.run("while true; do :; done");
  assert.notEqual(r.exitCode, 0);
});

// --- tarDirectory(): just-bash's own `tar` command, running inside QuickJS ---

test("tarDirectory() produces a valid archive with matching content", async () => {
  const sandbox = await freshSandbox();
  await sandbox.run("mkdir -p input && echo -n alpha > input/a.txt && echo -n beta-content > input/b.txt");

  const result = await sandbox.tarDirectory("input", "archive.tar");
  assert.equal(result.exitCode, 0);
  const archivePath = join(sandbox.workspacePath, "archive.tar");
  assert.ok(existsSync(archivePath));

  const listing = execFileSync("tar", ["-tf", archivePath], { encoding: "utf8" });
  assert.match(listing, /a\.txt/);
  assert.match(listing, /b\.txt/);

  const extractedA = execFileSync("tar", ["-xOf", archivePath, "./a.txt"], { encoding: "utf8" });
  assert.equal(extractedA, "alpha");
});

test("tarDirectory() round-trips binary content, including embedded NUL bytes", async () => {
  const sandbox = await freshSandbox();
  await sandbox.run("mkdir -p input");

  // Bytes covering the full 0..255 range, including 0x00 -- the byte value
  // that broke the previous (js-exec-based) version of this experiment.
  const bytes = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  writeFileSync(join(sandbox.workspacePath, "input", "allbytes.bin"), bytes);

  await sandbox.tarDirectory("input", "archive.tar");
  const archivePath = join(sandbox.workspacePath, "archive.tar");
  const extracted = execFileSync("tar", ["-xOf", archivePath, "./allbytes.bin"]);
  assert.deepEqual(extracted, bytes);
});

test("tarDirectory() rejects a missing source directory with a clear error", async () => {
  const sandbox = await freshSandbox();
  await assert.rejects(() => sandbox.tarDirectory("does-not-exist", "out.tar"), /tarDirectory failed/);
});

test("dispose() does not throw even after processing enough data to hit the known QuickJS teardown limitation", async () => {
  const sandbox = await freshSandbox();
  await sandbox.run("mkdir -p bulk");
  for (let i = 0; i < 20; i++) {
    await sandbox.run(`head -c 51200 /dev/zero | tr '\\0' 'x' > bulk/f${i}.txt`);
  }
  const result = await sandbox.tarDirectory("bulk", "bulk.tar");
  assert.equal(result.exitCode, 0);
  assert.doesNotThrow(() => sandbox.dispose());
  sandboxes = sandboxes.filter((s) => s !== sandbox); // already disposed, skip in after()
});
