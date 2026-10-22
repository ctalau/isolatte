// usage: node bench.js THREADS [PASSES] < file-list
//   VERBOSE=1 prints errors; PARSE_ONLY=1 runs saxes without validating.
// THREADS worker_threads pull file indexes from a shared atomic counter. Each
// pass re-validates the whole list in the same workers and prints one line:
// pass 1 is cold, later passes are JIT-warmed.
'use strict';
const fs = require('fs');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

if (isMainThread) {
  const nthreads = Number(process.argv[2] || 1);
  const passes = Number(process.argv[3] || 1);
  const files = fs.readFileSync(0, 'utf8').split('\n').filter((l) => l);
  const counter = new Int32Array(new SharedArrayBuffer(4));
  const mode = process.env.PARSE_ONLY ? 'parse-only-js' : 'compiled-js';
  const workers = [];
  let ready = 0, pass = 0, done, bytes, invalid, errors, t0;
  const startPass = () => {
    pass++; done = 0; bytes = 0; invalid = 0; errors = 0;
    Atomics.store(counter, 0, 0);
    t0 = process.hrtime.bigint();
    workers.forEach((w) => w.postMessage('go'));
  };
  for (let i = 0; i < nthreads; i++) {
    const w = new Worker(__filename, {
      workerData: { files, counter, verbose: !!process.env.VERBOSE, parseOnly: !!process.env.PARSE_ONLY },
    });
    w.on('message', (m) => {
      // Start the clock once every worker has loaded the compiled tables.
      if (m.ready) { if (++ready === nthreads) startPass(); return; }
      if (pass === 1) for (const line of m.out) console.log(line);
      bytes += m.bytes; invalid += m.invalid; errors += m.errors;
      if (++done < nthreads) return;
      const s = Number(process.hrtime.bigint() - t0) / 1e9;
      console.log(`validator=${mode} pass=${pass} threads=${nthreads} files=${files.length} bytes=${bytes} ` +
        `invalid_files=${invalid} errors=${errors} dtd_load_s=0.000 seconds=${s.toFixed(3)} ` +
        `files_per_s=${Math.round(files.length / s)} MB_per_s=${(bytes / s / 1e6).toFixed(1)}`);
      if (pass < passes) startPass(); else workers.forEach((x) => x.terminate());
    });
    workers.push(w);
  }
} else {
  const { validate, parseOnly } = require('./validator');
  const { files, counter, verbose } = workerData;
  const run = workerData.parseOnly ? parseOnly : validate;
  parentPort.on('message', () => {
    let bytes = 0, invalid = 0, errors = 0;
    const out = [];
    for (let i; (i = Atomics.add(counter, 0, 1)) < files.length;) {
      const text = fs.readFileSync(files[i], 'utf8');
      bytes += Buffer.byteLength(text);
      const r = run(text, verbose);
      if (r.errors) {
        invalid++; errors += r.errors;
        out.push(`INVALID ${files[i]} ${r.errors}`);
        if (r.messages) for (const m of r.messages) out.push(`  ${m}`);
      }
    }
    parentPort.postMessage({ out, bytes, invalid, errors });
  });
  parentPort.postMessage({ ready: true });
}
