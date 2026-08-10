// Benchmarks tarring 1000 files (2 KiB each) two ways:
//   1. BashSandbox.tarDirectory() -- a bash script (`tar -cf ...`) running
//      through just-bash's own `tar` command, with the *entire* interpreter
//      executing as guest code inside a real QuickJS WASM VM, reading each
//      file through the workspace-scoped host fs bridge.
//   2. The system `tar` binary, invoked directly via child_process (no
//      sandbox at all).
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
    // Pseudo-random-ish content (not all zero, not all identical), including
    // every byte value 0-255 as it cycles -- not a best case for either side.
    for (let j = 0; j < FILE_SIZE; j++) buf[j] = (i * 31 + j * 17) % 256;
    writeFileSync(join(dir, name), buf);
  }
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function benchmarkSandboxTar() {
  const durations = [];
  let lastBytes = 0;
  for (let i = 0; i < RUNS; i++) {
    const root = mkdtempSync(join(tmpdir(), "qjs-bash-bench-sandbox-"));
    const inputDir = join(root, "input");
    generateFixtures(inputDir);
    const sandbox = await BashSandbox.create({ workspace: root });
    const start = Date.now();
    const result = await sandbox.tarDirectory("input", "out.tar");
    if (result.exitCode !== 0) throw new Error(`tarDirectory failed: ${result.stderr}`);
    durations.push(Date.now() - start);
    lastBytes = statSync(join(root, "out.tar")).size;
    sandbox.dispose();
    rmSync(root, { recursive: true, force: true });
  }
  return { durations, bytes: lastBytes };
}

function benchmarkNativeTar() {
  const durations = [];
  let lastBytes = 0;
  for (let i = 0; i < RUNS; i++) {
    const root = mkdtempSync(join(tmpdir(), "qjs-bash-bench-native-"));
    const inputDir = join(root, "input");
    generateFixtures(inputDir);
    const tarPath = join(root, "out.tar");
    const start = Date.now();
    execFileSync("tar", ["-cf", tarPath, "-C", inputDir, "."]);
    durations.push(Date.now() - start);
    lastBytes = statSync(tarPath).size;
    rmSync(root, { recursive: true, force: true });
  }
  return { durations, bytes: lastBytes };
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

console.log(`Tarring ${FILE_COUNT} files x ${FILE_SIZE} bytes, ${RUNS} runs each (reporting median)\n`);

const sandboxResult = await benchmarkSandboxTar();
const nativeResult = benchmarkNativeTar();

const sandboxMs = report("BashSandbox.tarDirectory (whole interpreter in QuickJS)", sandboxResult);
const nativeMs = report("native tar", nativeResult);

console.log(`\nSlowdown vs native tar: ${(sandboxMs / nativeMs).toFixed(1)}x`);

process.exit(0);
