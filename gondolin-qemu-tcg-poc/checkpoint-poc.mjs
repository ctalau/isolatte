/**
 * Gondolin Checkpoint Startup-Time PoC
 *
 * Two-phase experiment:
 *   Phase 1 — cold boot: VM.create() → wait for Node → vm.checkpoint() → record time
 *   Phase 2 — warm resume: VmCheckpoint.load() → checkpoint.resume() → run code → record time
 *
 * The checkpoint is a disk-only snapshot (no RAM state). On resume, QEMU still
 * boots Alpine from the checkpointed qcow2 overlay, but any disk writes made
 * during the original boot are preserved, which may shorten init time.
 */

import { PassThrough, Writable } from "node:stream";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import {
  VM,
  VmCheckpoint,
  MemoryProvider,
  createHttpHooks,
} from "@earendil-works/gondolin";

import { tmpdir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

const START_MS = Date.now();
const timers = {};

function checkpoint(name) {
  const now = Date.now();
  timers[name] = now;
  const elapsed = now - START_MS;
  process.stderr.write(`[CHECKPOINT] ${String(name).padEnd(44)} +${elapsed}ms\n`);
}

checkpoint("process_start");

const CHECKPOINT_PATH = join(tmpdir(), "gondolin-tcg-checkpoint.qcow2");

// ---------------------------------------------------------------------------
// Host-side functions
// ---------------------------------------------------------------------------

const allowedHostFunctions = {
  async add({ a, b }) { return a + b; },
  async lookup({ key }) {
    return { hello: "world", answer: 42 }[key] ?? null;
  },
};

// ---------------------------------------------------------------------------
// Guest runner template (same as poc.mjs)
// ---------------------------------------------------------------------------

function makeGuestRunner(userCode) {
  return String.raw`
"use strict";
const readline = require("node:readline");
let nextId = 1;
const pending = new Map();
function timerEvent(name) {
  process.stdout.write("@@TIMER@@" + JSON.stringify({ event: name, ts: Date.now() }) + "\n");
}
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const p = pending.get(msg.id);
  if (!p) return;
  pending.delete(msg.id);
  timerEvent("rpc_response_received_id" + msg.id);
  if (msg.ok) p.resolve(msg.value);
  else p.reject(new Error(msg.error ?? "host RPC failed"));
});
function callHost(name, params) {
  const id = nextId++;
  timerEvent("rpc_call_sent_id" + id + "_fn_" + name);
  process.stdout.write("@@HOSTRPC@@" + JSON.stringify({ id, name, args: [params] }) + "\n");
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}
globalThis.host = new Proxy({}, {
  get(_t, prop) { return (params) => callHost(String(prop), params ?? {}); },
});
timerEvent("guest_code_start");
(async () => {
  try {
    ${userCode}
    process.stdout.write("@@DONE@@" + JSON.stringify({ ok: true }) + "\n");
  } catch (err) {
    process.stdout.write("@@DONE@@" + JSON.stringify({ ok: false, error: String(err?.stack ?? err) }) + "\n");
    process.exitCode = 1;
  }
})();
`;
}

// ---------------------------------------------------------------------------
// Host-side RPC handler
// ---------------------------------------------------------------------------

async function handleHostRpc(raw, guestIn) {
  let req;
  try {
    req = JSON.parse(raw);
    const fn = allowedHostFunctions[req.name];
    if (!fn) throw new Error(`function not allowed: ${req.name}`);
    const value = await fn(req.args?.[0] ?? {});
    guestIn.write(JSON.stringify({ id: req.id, ok: true, value }) + "\n");
  } catch (err) {
    guestIn.write(JSON.stringify({ id: req?.id, ok: false, error: String(err?.stack ?? err) }) + "\n");
  }
}

// ---------------------------------------------------------------------------
// Shared VM options factory
// ---------------------------------------------------------------------------

function makeVmOptions() {
  const { httpHooks, env } = createHttpHooks({
    allowedHosts: ["*.alpinelinux.org"],
    blockInternalRanges: true,
  });
  return {
    sessionLabel: "gondolin-checkpoint-poc",
    vfs: { mounts: { "/scratch": new MemoryProvider() } },
    httpHooks,
    env,
    allowWebSockets: false,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    sandbox: { accel: "tcg" },
    debugLog: null,
  };
}

// ---------------------------------------------------------------------------
// Phase 1 — cold boot + checkpoint creation
// ---------------------------------------------------------------------------

async function coldBootAndCheckpoint() {
  process.stderr.write("\n=== Phase 1: Cold boot + checkpoint ===\n");
  const PHASE_START = Date.now();

  const opts = makeVmOptions();
  opts.rootfs = { mode: "memory" };

  checkpoint("p1_vm_create_start");
  const vm = await VM.create(opts);
  checkpoint("p1_vm_created");

  try {
    checkpoint("p1_node_check_start");
    const nodeCheck = await vm.exec("which node || apk add --no-cache nodejs 2>&1", {
      stdout: "buffer",
      stderr: "buffer",
    });
    checkpoint("p1_node_check_done");
    process.stderr.write(`[p1] node check exit=${nodeCheck.exitCode} out=${nodeCheck.stdout.trim()}\n`);
    if (nodeCheck.exitCode !== 0) {
      throw new Error(`Node not available: ${nodeCheck.stderr}`);
    }

    checkpoint("p1_checkpoint_start");
    const ckpt = await vm.checkpoint(CHECKPOINT_PATH);
    checkpoint("p1_checkpoint_done");

    const totalMs = Date.now() - PHASE_START;
    process.stderr.write(`[p1] checkpoint saved to: ${ckpt.path}\n`);
    process.stderr.write(`[p1] Phase 1 total: ${totalMs}ms\n`);
    return ckpt;
  } catch (err) {
    // vm.checkpoint() calls vm.close() internally; only close if not checkpointed
    try { await vm.close(); } catch {}
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Phase 2 — warm resume + run user code
// ---------------------------------------------------------------------------

async function resumeAndRun(userCode) {
  process.stderr.write("\n=== Phase 2: Warm resume from checkpoint ===\n");
  const PHASE_START = Date.now();

  checkpoint("p2_load_start");
  const ckpt = VmCheckpoint.load(CHECKPOINT_PATH);
  checkpoint("p2_load_done");

  checkpoint("p2_resume_start");
  const vm = await ckpt.resume({
    sessionLabel: "gondolin-checkpoint-resume",
    vfs: { mounts: { "/scratch": new MemoryProvider() } },
    allowWebSockets: false,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    sandbox: { accel: "tcg" },
    debugLog: null,
  });
  checkpoint("p2_vm_created");

  try {
    // Wait for the VM to be ready for exec (same node-check as cold boot)
    checkpoint("p2_node_check_start");
    const nodeCheck = await vm.exec("which node", { stdout: "buffer", stderr: "buffer" });
    checkpoint("p2_node_check_done");
    process.stderr.write(`[p2] node check exit=${nodeCheck.exitCode} out=${nodeCheck.stdout.trim()}\n`);
    if (nodeCheck.exitCode !== 0) {
      throw new Error(`Node not found on resumed VM: ${nodeCheck.stderr}`);
    }

    // Write and execute user code
    checkpoint("p2_script_write_start");
    const runner = makeGuestRunner(userCode);
    await vm.fs.writeFile("/scratch/runner.js", runner);
    checkpoint("p2_script_written");

    let procRef = null;
    const guestIn = new PassThrough();
    let stdoutBuffer = "";
    let done = null;
    let firstOutputSeen = false;

    const guestOut = new Writable({
      write(chunk, _enc, cb) {
        stdoutBuffer += chunk.toString("utf8");
        for (;;) {
          const nl = stdoutBuffer.indexOf("\n");
          if (nl === -1) break;
          const line = stdoutBuffer.slice(0, nl);
          stdoutBuffer = stdoutBuffer.slice(nl + 1);

          if (!firstOutputSeen) {
            firstOutputSeen = true;
            checkpoint("p2_first_guest_output");
          }

          if (line.startsWith("@@TIMER@@")) {
            try {
              const evt = JSON.parse(line.slice("@@TIMER@@".length));
              const hostNow = Date.now();
              process.stderr.write(
                `[GUEST-TIMER] ${evt.event.padEnd(48)} +${hostNow - START_MS}ms\n`,
              );
            } catch {}
          } else if (line.startsWith("@@HOSTRPC@@")) {
            handleHostRpc(line.slice("@@HOSTRPC@@".length), guestIn);
          } else if (line.startsWith("@@DONE@@")) {
            checkpoint("p2_guest_done");
            done = JSON.parse(line.slice("@@DONE@@".length));
            guestIn.end();
            if (procRef) procRef.end();
          } else if (line.trim()) {
            process.stdout.write(`[guest] ${line}\n`);
          }
        }
        cb();
      },
    });

    checkpoint("p2_exec_start");
    const proc = vm.exec(["/usr/bin/env", "node", "/scratch/runner.js"], {
      stdin: true,
      stdout: "pipe",
      stderr: "pipe",
      pty: false,
    });
    procRef = proc;
    proc.attach(guestIn, guestOut, process.stderr);
    checkpoint("p2_exec_attached");

    const result = await proc;
    checkpoint("p2_exec_completed");

    if (!done) throw new Error(`guest exited without @@DONE@@ (exit=${result.exitCode})`);
    if (!done.ok) throw new Error(`guest error:\n${done.error}`);

    const totalMs = Date.now() - PHASE_START;
    process.stderr.write(`[p2] Phase 2 total: ${totalMs}ms\n`);
    return { exitCode: result.exitCode };
  } finally {
    checkpoint("p2_vm_close_start");
    await vm.close();
    checkpoint("p2_vm_closed");
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const USER_CODE = `
  const sum = await host.add({ a: 2, b: 40 });
  const val = await host.lookup({ key: "hello" });
  console.log(JSON.stringify({ sum, val }));
`;

try {
  // Phase 1: always create a fresh checkpoint so we measure real cold-boot time
  if (existsSync(CHECKPOINT_PATH)) {
    process.stderr.write(`[info] removing stale checkpoint: ${CHECKPOINT_PATH}\n`);
    import("node:fs").then(({ unlinkSync }) => unlinkSync(CHECKPOINT_PATH));
  }
  await coldBootAndCheckpoint();

  // Phase 2: resume from checkpoint and run code
  const result = await resumeAndRun(USER_CODE);

  checkpoint("all_done");

  process.stderr.write("\n=== Timing Summary (ms from process start) ===\n");
  for (const [k, v] of Object.entries(timers)) {
    process.stderr.write(`  ${k.padEnd(52)} +${v - START_MS}ms\n`);
  }

  // Derived metrics
  const p1Boot = timers["p1_node_check_done"] - timers["p1_vm_create_start"];
  const p1CkptTime = timers["p1_checkpoint_done"] - timers["p1_checkpoint_start"];
  const p2Boot = timers["p2_node_check_done"] - timers["p2_resume_start"];

  process.stderr.write("\n=== Key Metrics ===\n");
  process.stderr.write(`  Cold boot to first-exec-ready:    ${p1Boot}ms\n`);
  process.stderr.write(`  Checkpoint creation time:         ${p1CkptTime}ms\n`);
  process.stderr.write(`  Warm resume to first-exec-ready:  ${p2Boot}ms\n`);
  if (p1Boot > 0 && p2Boot > 0) {
    const ratio = (p1Boot / p2Boot).toFixed(1);
    process.stderr.write(`  Speedup (cold/warm):              ${ratio}x\n`);
  }

  process.stderr.write(`\nFinal exit code: ${result.exitCode}\n`);
} catch (err) {
  checkpoint("fatal_error");
  process.stderr.write(`\nFATAL: ${err.message ?? err}\n`);
  if (err.stack) process.stderr.write(err.stack + "\n");
  process.exit(1);
}
