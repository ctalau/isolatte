// Benchmarks zipping 1000 files (2 KiB each) two ways:
//   1. BashSandbox.zipDirectory() — a bash script that shells out to js-exec,
//      which runs the archive-building code inside an actual QuickJS WASM VM,
//      reading each file through the workspace-scoped fs bridge.
//   2. The system `zip` binary, invoked directly via child_process (no
//      sandbox at all) — both in its default deflate mode and in `-0`
//      (store, no compression) mode, since our sandboxed implementation only
//      implements store and a deflate-vs-store comparison alone would be
//      misleading.
//
// Run with: npm run benchmark
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { BashSandbox } from "../src/bash-sandbox.mjs";

const FILE_COUNT = 1000;
const FILE_SIZE = 2048;
const RUNS = 3;

function generateFixtures(dir) {
  mkdirSync(dir, { recursive: true });
  for (let i = 0; i < FILE_COUNT; i++) {
    const name = `file_${String(i).padStart(4, "0")}.txt`;
    const buf = Buffer.alloc(FILE_SIZE);
    // Pseudo-random-ish content (not all zero, not all identical) so this
    // isn't a best case for compression or for any accidental all-zero bug.
    for (let j = 0; j < FILE_SIZE; j++) buf[j] = (i * 31 + j * 17) % 256;
    writeFileSync(join(dir, name), buf);
  }
}

function timeMs(fn) {
  const start = process.hrtime.bigint();
  const result = fn();
  const end = process.hrtime.bigint();
  return { result, ms: Number(end - start) / 1e6 };
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function benchmarkSandboxZip() {
  const durations = [];
  let lastBytes = 0;
  for (let i = 0; i < RUNS; i++) {
    const root = mkdtempSync(join(tmpdir(), "qjs-bash-bench-sandbox-"));
    const inputDir = join(root, "input");
    generateFixtures(inputDir);
    const sandbox = new BashSandbox({ workspace: root, enableZip: true });
    const r = await sandbox.zipDirectory("input", "out.zip");
    durations.push(r.durationMs);
    lastBytes = r.writtenBytes;
    rmSync(root, { recursive: true, force: true });
  }
  return { durations, bytes: lastBytes };
}

function benchmarkNativeZip(extraArgs, label) {
  const durations = [];
  let lastBytes = 0;
  for (let i = 0; i < RUNS; i++) {
    const root = mkdtempSync(join(tmpdir(), "qjs-bash-bench-native-"));
    const inputDir = join(root, "input");
    generateFixtures(inputDir);
    const zipPath = join(root, "out.zip");
    const { ms } = timeMs(() => {
      execFileSync("zip", ["-q", "-r", ...extraArgs, zipPath, "."], { cwd: inputDir });
    });
    durations.push(ms);
    lastBytes = statSync(zipPath).size;
    rmSync(root, { recursive: true, force: true });
  }
  return { durations, bytes: lastBytes, label };
}

function report(name, { durations, bytes }) {
  const med = median(durations);
  console.log(
    `${name.padEnd(38)} median ${med.toFixed(1).padStart(8)} ms   runs: [${durations
      .map((d) => d.toFixed(1))
      .join(", ")}] ms   archive: ${(bytes / 1024).toFixed(1)} KiB`
  );
  return med;
}

console.log(`Zipping ${FILE_COUNT} files x ${FILE_SIZE} bytes, ${RUNS} runs each (reporting median)\n`);

const sandboxResult = await benchmarkSandboxZip();
const nativeStoreResult = benchmarkNativeZip(["-0"], "native zip -0 (store)");
const nativeDeflateResult = benchmarkNativeZip([], "native zip (default deflate)");

const sandboxMs = report("BashSandbox.zipDirectory (QuickJS, store)", sandboxResult);
const nativeStoreMs = report("native zip -0 (store)", nativeStoreResult);
const nativeDeflateMs = report("native zip (default deflate)", nativeDeflateResult);

console.log("\nSlowdown vs native:");
console.log(`  vs native zip -0 (store, apples-to-apples): ${(sandboxMs / nativeStoreMs).toFixed(1)}x`);
console.log(`  vs native zip (default deflate):            ${(sandboxMs / nativeDeflateMs).toFixed(1)}x`);

process.exit(0);
