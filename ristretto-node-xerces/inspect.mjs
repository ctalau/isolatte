import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { createParser } from './host.mjs';

const started = performance.now();
const parser = await createParser();
const result = parser.parseFile(new URL('./sample.xml', import.meta.url).pathname);
const elapsedMs = Math.round(performance.now() - started);
const probe = parser.probe();
const stats = parser.stats();
const generated = readFileSync(new URL('./generated/xerces.js', import.meta.url), 'utf8');
const declaredInterfaces = [...generated.matchAll(/imports\['([^']+)'\]/g)].map(match => match[1]);
const linkedOperations = [...new Set([...generated.matchAll(/iface="([^"]+)", function="([^"]+)"/g)].map(match => `${match[1]}#${match[2]}`))].sort();
const filesystemSource = readFileSync(new URL('../browser/filesystem.js', import.meta.resolve('@bytecodealliance/preview2-shim')));
const coreModules = [];
for (const name of readdirSync(new URL('./generated/', import.meta.url)).filter(name => name.endsWith('.wasm'))) {
  const bytes = readFileSync(new URL(`./generated/${name}`, import.meta.url));
  const module = await WebAssembly.compile(bytes);
  coreModules.push({ name, bytes: bytes.byteLength, imports: WebAssembly.Module.imports(module) });
}
const report = {
  recordedAt: new Date().toISOString(), node: process.version, platform: process.platform,
  ristrettoCommit: 'dcd45fb452d6956122a9985096260310a22b4d44', elapsedMs, result, probe,
  ...stats,
  javascriptFilesystemImplementation: { sourceBytes: filesystemSource.byteLength, gzipBytes: gzipSync(filesystemSource).byteLength },
  declaredInterfaces: [...new Set(declaredInterfaces)].sort(), linkedOperations, coreModules,
};
writeFileSync(new URL('./results/sandbox-report.json', import.meta.url), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ elapsedMs, result, probe, filesystem: stats.currentFilesystem, wasmMemories: stats.wasmMemories, declaredInterfaces: report.declaredInterfaces, usedOperations: stats.wasiCalls }, null, 2));
