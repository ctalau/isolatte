import { dirname, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
const args = process.argv.slice(2);
const disk = args.includes('--disk');
const { createParser } = await import(disk ? './host-disk.mjs' : './host.mjs');
const file = resolve(args.find((argument) => argument !== '--disk') ?? 'sample.xml');
try {
  const start = performance.now();
  const parser = await createParser(dirname(file));
  const result = parser.parseFile(file);
  console.log(JSON.stringify({
    host: `Node ${process.version}`,
    pid: process.pid,
    execution: 'Ristretto WASM inside Node; no Java subprocess',
    filesystem: disk ? 'Node disk mounts' : 'Node files loaded into a JS-hosted memory filesystem',
    file,
    ...result,
    elapsedMs: Math.round(performance.now() - start),
  }, null, 2));
} catch (error) {
  console.error('XML parse failed:', error.payload ?? error.message ?? String(error));
  process.exitCode = 1;
}
