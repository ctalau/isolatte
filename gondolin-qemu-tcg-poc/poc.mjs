/**
 * Gondolin QEMU-TCG PoC
 *
 * Tests:
 *  - TCG (software emulation) boot without /dev/kvm
 *  - JSON-RPC host-call protocol over exec stdin/stdout
 *  - Timing checkpoints through the full invocation flow
 *
 * Key API notes (Gondolin 0.5.0):
 *  - sandbox.accel="tcg" forces software emulation
 *  - vm.getHostPid() does NOT exist; QEMU PID found via pgrep
 *  - rootfs.mode="memory" → writable throwaway disk
 *  - vfs.mounts["/scratch"] = MemoryProvider → in-memory scratchpad
 *  - createHttpHooks returns { httpHooks, env } for VM.create()
 */

import { PassThrough, Writable } from "node:stream";
import { execSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import {
  VM,
  MemoryProvider,
  createHttpHooks,
} from "@earendil-works/gondolin";

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

const START_MS = Date.now();
const timers = {};

function checkpoint(name) {
  const now = Date.now();
  timers[name] = now;
  const elapsed = now - START_MS;
  process.stderr.write(`[CHECKPOINT] ${String(name).padEnd(40)} +${elapsed}ms\n`);
}

checkpoint("process_start");

// ---------------------------------------------------------------------------
// Host-side functions exposed to guest code
// ---------------------------------------------------------------------------

const allowedHostFunctions = {
  async add({ a, b }) {
    return a + b;
  },
  async lookup({ key }) {
    const table = { hello: "world", answer: 42 };
    return table[key] ?? null;
  },
};

// ---------------------------------------------------------------------------
// Guest runner template
//
// Embedded into /scratch/runner.js inside the VM. Communicates with the host
// over exec stdin/stdout using three line prefixes:
//   @@TIMER@@{json}     timing event (handled host-side, not forwarded)
//   @@HOSTRPC@@{json}   JSON-RPC call from guest to host
//   @@DONE@@{json}      execution finished (ok/error)
//
// Host sends JSON-RPC responses back via stdin:
//   {id, ok, value}   or   {id, ok:false, error}
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
    process.stdout.write("@@DONE@@" + JSON.stringify({
      ok: false, error: String(err?.stack ?? err),
    }) + "\n");
    process.exitCode = 1;
  }
})();
`;
}

// ---------------------------------------------------------------------------
// QEMU process inspection (replaces the non-existent vm.getHostPid())
//
// vm.getHostPid() is NOT part of Gondolin 0.5.0's public API.
// Instead we scan /proc directly, matching only entries whose argv[0]
// contains "qemu-system" so we don't match processes that merely mention
// "qemu" in their argument lists (e.g. the parent Node process itself).
// ---------------------------------------------------------------------------

function findQemuProcesses() {
  const results = [];
  try {
    for (const entry of readdirSync("/proc")) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        const raw = readFileSync(`/proc/${entry}/cmdline`, "ascii");
        const args = raw.split("\0").filter(Boolean);
        // argv[0] must be the qemu-system binary, not just any process that
        // happens to have "qemu" somewhere in its argument list.
        if (args[0] && args[0].includes("qemu-system")) {
          results.push({ pid: entry, cmdline: args.join(" "), args });
        }
      } catch {
        // process may have exited; skip
      }
    }
  } catch {
    // /proc not readable; skip
  }
  return results;
}

// ---------------------------------------------------------------------------
// Host-side RPC handler (async, fire-and-forget per call)
// ---------------------------------------------------------------------------

async function handleHostRpc(raw, guestIn) {
  let req;
  try {
    req = JSON.parse(raw);
    checkpoint(`host_rpc_received_id${req.id}_fn_${req.name}`);

    const fn = allowedHostFunctions[req.name];
    if (!fn) throw new Error(`function not allowed: ${req.name}`);

    const value = await fn(req.args?.[0] ?? {});
    checkpoint(`host_rpc_returned_id${req.id}_fn_${req.name}`);

    guestIn.write(JSON.stringify({ id: req.id, ok: true, value }) + "\n");
    checkpoint(`host_rpc_sent_id${req.id}_fn_${req.name}`);
  } catch (err) {
    guestIn.write(
      JSON.stringify({ id: req?.id, ok: false, error: String(err?.stack ?? err) }) + "\n",
    );
  }
}

// ---------------------------------------------------------------------------
// Main sandbox runner
// ---------------------------------------------------------------------------

async function runUntrusted(userCode) {
  // Allow apk mirrors so we can install Node if absent.
  // For production: use allowedHosts:[] and isRequestAllowed:()=>false.
  const { httpHooks, env } = createHttpHooks({
    allowedHosts: ["*.alpinelinux.org"],
    blockInternalRanges: true,
  });

  // ── VM boot ──────────────────────────────────────────────────────────────
  checkpoint("vm_create_start");

  const vm = await VM.create({
    sessionLabel: "gondolin-tcg-poc",
    rootfs: { mode: "memory" },
    vfs: { mounts: { "/scratch": new MemoryProvider() } },
    httpHooks,
    env,
    allowWebSockets: false,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    sandbox: { accel: "tcg" },  // force software emulation
    debugLog: null,             // suppress internal debug noise
  });

  checkpoint("vm_created");

  try {
    // ── Ensure Node.js is available ─────────────────────────────────────────
    // (This first exec also waits for the VM to be fully booted under TCG.)
    checkpoint("node_check_start");
    const nodeCheck = await vm.exec("which node || apk add --no-cache nodejs 2>&1", {
      stdout: "buffer",
      stderr: "buffer",
    });
    checkpoint("node_check_done");
    process.stderr.write(`[setup] node check exit=${nodeCheck.exitCode} out=${nodeCheck.stdout.trim()}\n`);
    if (nodeCheck.exitCode !== 0) {
      throw new Error(`Node.js not available and apk install failed:\n${nodeCheck.stderr}`);
    }

    // ── Verify QEMU PID and TCG via /proc cmdline ───────────────────────────
    // Done here (after first exec) because VM.create() returns only ~12ms
    // after spawn — the qemu-system process may not appear in /proc yet.
    const procs = findQemuProcesses();
    if (procs.length === 0) {
      process.stderr.write("[WARN] no qemu-system process found in /proc\n");
    }
    for (const { pid, cmdline, args } of procs) {
      const accelArg = args[args.indexOf("-accel") + 1] ?? "(not set)";
      const hasTcg = cmdline.includes("tcg");
      process.stderr.write(
        `[QEMU] pid=${pid} -accel=${accelArg} cmdline_has_tcg=${hasTcg}\n` +
        `[QEMU] argv: ${args.slice(0, 6).join(" ")} ...\n`,
      );
    }

    // ── Write guest runner ──────────────────────────────────────────────────
    checkpoint("script_write_start");
    const runner = makeGuestRunner(userCode);
    await vm.fs.writeFile("/scratch/runner.js", runner);
    checkpoint("script_written");

    // ── Set up streaming I/O ────────────────────────────────────────────────
    let procRef = null;  // captured after exec, used to send EOF on DONE
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
            checkpoint("first_guest_output");
          }

          if (line.startsWith("@@TIMER@@")) {
            try {
              const evt = JSON.parse(line.slice("@@TIMER@@".length));
              const hostNow = Date.now();
              timers[`guest::${evt.event}`] = hostNow;
              process.stderr.write(
                `[GUEST-TIMER] ${evt.event.padEnd(48)} +${hostNow - START_MS}ms` +
                ` (guest_epoch=${evt.ts})\n`,
              );
            } catch {}
          } else if (line.startsWith("@@HOSTRPC@@")) {
            handleHostRpc(line.slice("@@HOSTRPC@@".length), guestIn);
          } else if (line.startsWith("@@DONE@@")) {
            checkpoint("guest_done_marker");
            done = JSON.parse(line.slice("@@DONE@@".length));
            // Send EOF so the guest readline closes and the process exits.
            guestIn.end();
            if (procRef) procRef.end();
          } else if (line.trim()) {
            process.stdout.write(`[guest] ${line}\n`);
          }
        }
        cb();
      },
    });

    // ── Execute runner ──────────────────────────────────────────────────────
    checkpoint("exec_call_start");
    const proc = vm.exec(["/usr/bin/env", "node", "/scratch/runner.js"], {
      stdin: true,
      stdout: "pipe",
      stderr: "pipe",
      pty: false,
    });
    procRef = proc;

    proc.attach(guestIn, guestOut, process.stderr);
    checkpoint("exec_attached");

    const result = await proc;
    checkpoint("exec_completed");

    if (!done) throw new Error(`guest exited without @@DONE@@ (exit=${result.exitCode})`);
    if (!done.ok) throw new Error(`guest error:\n${done.error}`);

    return { exitCode: result.exitCode };
  } finally {
    checkpoint("vm_close_start");
    await vm.close();
    checkpoint("vm_closed");
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

try {
  const result = await runUntrusted(`
    const sum = await host.add({ a: 2, b: 40 });
    const val = await host.lookup({ key: "hello" });
    console.log(JSON.stringify({ sum, val }));
  `);

  checkpoint("all_done");

  process.stderr.write("\n=== Timing Summary (ms from process start) ===\n");
  for (const [k, v] of Object.entries(timers)) {
    process.stderr.write(`  ${k.padEnd(52)} +${v - START_MS}ms\n`);
  }

  process.stderr.write(`\nFinal exit code: ${result.exitCode}\n`);
} catch (err) {
  checkpoint("fatal_error");
  process.stderr.write(`\nFATAL: ${err.message ?? err}\n`);
  process.exit(1);
}
