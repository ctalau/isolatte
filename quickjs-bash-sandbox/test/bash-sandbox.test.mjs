import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { BashSandbox } from "../src/bash-sandbox.mjs";

let workDirs = [];

function freshWorkspace() {
  const dir = mkdtempSync(join(tmpdir(), "quickjs-bash-sandbox-test-"));
  workDirs.push(dir);
  return dir;
}

after(() => {
  for (const dir of workDirs) rmSync(dir, { recursive: true, force: true });
});

// --- basic execution -------------------------------------------------------

test("runs a simple script and captures stdout/exitCode", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  const r = await sandbox.run('echo "hello world"');
  assert.equal(r.stdout, "hello world\n");
  assert.equal(r.exitCode, 0);
  assert.equal(typeof r.durationMs, "number");
});

test("nonzero exit code and stderr are surfaced, not thrown", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  const r = await sandbox.run("cat /no/such/file");
  assert.notEqual(r.exitCode, 0);
  assert.match(r.stderr, /no such file|not found/i);
});

test("pipes, redirection, and variables work", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  const r = await sandbox.run('X=42; echo "value=$X" | tr a-z A-Z > out.txt; cat out.txt');
  assert.equal(r.stdout, "VALUE=42\n");
});

// --- workspace read/write ---------------------------------------------------

test("files written by the sandbox land in the real workspace directory", async () => {
  const ws = freshWorkspace();
  const sandbox = new BashSandbox({ workspace: ws });
  await sandbox.run('echo "persisted" > note.txt');
  const onDisk = readFileSync(join(ws, "note.txt"), "utf8");
  assert.equal(onDisk, "persisted\n");
});

test("filesystem changes persist across separate run() calls, env does not", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  await sandbox.run("echo persisted-content > shared.txt; export CARRY=yes");
  const r = await sandbox.run('cat shared.txt; echo "CARRY=${CARRY:-unset}"');
  assert.equal(r.stdout, "persisted-content\nCARRY=unset\n");
});

test("pre-existing files on disk are visible to the sandbox", async () => {
  const ws = freshWorkspace();
  const sandbox = new BashSandbox({ workspace: ws });
  execFileSync("bash", ["-c", `echo seeded > ${join(ws, "seed.txt")}`]);
  const r = await sandbox.run("cat seed.txt");
  assert.equal(r.stdout, "seeded\n");
});

// --- security: workspace confinement ---------------------------------------

test("'..' traversal clamps at the workspace root instead of escaping it", async () => {
  const ws = freshWorkspace();
  const sandbox = new BashSandbox({ workspace: ws });
  const r = await sandbox.run("cd sub 2>/dev/null; mkdir -p sub && cd sub && echo escaped > ../../../../outside.txt; echo exit=$?");
  assert.match(r.stdout, /exit=0/);
  // The write must not have reached any real ancestor directory of the workspace.
  assert.equal(existsSync(join(ws, "..", "outside.txt")), false);
  assert.equal(existsSync(join(tmpdir(), "outside.txt")), false);
  // It should have landed inside the workspace, clamped at the virtual root.
  assert.equal(existsSync(join(ws, "outside.txt")), true);
});

test("absolute paths outside the workspace are not visible", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  const r = await sandbox.run("cat /etc/passwd");
  assert.notEqual(r.exitCode, 0);
  assert.doesNotMatch(r.stdout, /root:/);
});

test("network is disabled by default (curl does not exist)", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  const r = await sandbox.run("curl --version");
  assert.notEqual(r.exitCode, 0);
});

// --- resource limits ---------------------------------------------------------

test("runaway loops are stopped by execution limits, not left to hang", async () => {
  const sandbox = new BashSandbox({
    workspace: freshWorkspace(),
    executionLimits: { maxExecutionTimeMs: 2_000 },
  });
  const r = await sandbox.run("while true; do :; done");
  assert.notEqual(r.exitCode, 0);
});

// --- js-exec / QuickJS ------------------------------------------------------

test("js-exec is unavailable unless enableZip (javascript) is turned on", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  const r = await sandbox.run('js-exec -c "console.log(1)"');
  assert.notEqual(r.exitCode, 0);
});

test("js-exec runs JavaScript inside the QuickJS sandbox and can reach the workspace fs bridge", async () => {
  const ws = freshWorkspace();
  const sandbox = new BashSandbox({ workspace: ws, enableZip: true });
  await sandbox.run('echo seed > seed.txt');
  const r = await sandbox.run(
    'js-exec -c "const c = fs.readFileSync(\'/seed.txt\', \'utf8\'); fs.writeFileSync(\'/from-quickjs.txt\', c.toUpperCase());"'
  );
  assert.equal(r.exitCode, 0);
  assert.equal(readFileSync(join(ws, "from-quickjs.txt"), "utf8"), "SEED\n");
});

// --- zipDirectory ------------------------------------------------------------

test("zipDirectory() throws when the sandbox was not built with enableZip", async () => {
  const sandbox = new BashSandbox({ workspace: freshWorkspace() });
  await assert.rejects(() => sandbox.zipDirectory("input", "out.zip"));
});

test("zipDirectory() produces a valid archive with matching content", async () => {
  const ws = freshWorkspace();
  const sandbox = new BashSandbox({ workspace: ws, enableZip: true });
  await sandbox.run('mkdir -p input && printf "alpha" > input/a.txt && printf "beta-content" > input/b.txt');

  const result = await sandbox.zipDirectory("input", "archive.zip");
  assert.equal(result.fileCount, 2);
  assert.equal(result.writtenBytes, result.archiveBytes);
  assert.ok(existsSync(join(ws, "archive.zip")));

  const listing = execFileSync("unzip", ["-l", join(ws, "archive.zip")], { encoding: "utf8" });
  assert.match(listing, /a\.txt/);
  assert.match(listing, /b\.txt/);

  const extractedA = execFileSync("unzip", ["-p", join(ws, "archive.zip"), "a.txt"], { encoding: "utf8" });
  assert.equal(extractedA, "alpha");

  const testOutput = execFileSync("unzip", ["-tq", join(ws, "archive.zip")], { encoding: "utf8" });
  assert.match(testOutput, /No errors detected/);
});

test("zipDirectory() round-trips binary content, including embedded NUL bytes", async () => {
  const ws = freshWorkspace();
  const sandbox = new BashSandbox({ workspace: ws, enableZip: true });
  await sandbox.run("mkdir -p input");

  // Write a file whose bytes cover the full 0..255 range, including 0x00 —
  // the byte value that broke earlier (buggier) implementations of the zip
  // helper. See zip-bootstrap.mjs for the full story.
  const bytes = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const { writeFileSync } = await import("node:fs");
  writeFileSync(join(ws, "input", "allbytes.bin"), bytes);

  await sandbox.zipDirectory("input", "archive.zip");
  const extracted = execFileSync("unzip", ["-p", join(ws, "archive.zip"), "allbytes.bin"]);
  assert.deepEqual(extracted, bytes);
});
