// usage: node wasm-check.js VALIDATOR.wasm < file-list
// Runs the wasm build of the compiled validator over the files (one thread)
// and prints INVALID lines plus a summary, like the native harness.
'use strict';
const fs = require('fs');
const bytes = fs.readFileSync(process.argv[2]);
const mod = new WebAssembly.Module(bytes);
console.log('imports:', JSON.stringify(WebAssembly.Module.imports(mod)));
console.log('exports:', WebAssembly.Module.exports(mod).map((e) => e.name).join(' '));
const w = new WebAssembly.Instance(mod, {}).exports;
const files = fs.readFileSync(0, 'utf8').split('\n').filter((l) => l);
const docs = files.map((f) => fs.readFileSync(f));
let invalid = 0, total = 0;
const t0 = process.hrtime.bigint();
for (let pass = 0; pass < 2; pass++) {
  invalid = 0; total = 0;
  for (let i = 0; i < docs.length; i++) {
    const d = docs[i];
    const p = w.alloc(d.length);
    new Uint8Array(w.memory.buffer, p, d.length).set(d);
    const n = w.validate(p, d.length, 1);
    w.dealloc(p, d.length);
    total += d.length;
    if (n) {
      invalid++;
      if (pass === 0) {
        const m = new TextDecoder().decode(new Uint8Array(w.memory.buffer, w.messages_ptr(), w.messages_len()));
        console.log(`INVALID ${files[i]} ${n}  ${m.split('\n')[0]}`);
      }
    }
  }
}
const s = Number(process.hrtime.bigint() - t0) / 1e9 / 2;
console.log(`files=${docs.length} invalid=${invalid} seconds_per_pass=${s.toFixed(3)} files_per_s=${Math.round(docs.length / s)}`);
