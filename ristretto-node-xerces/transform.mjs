import { dirname, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createParser } from './host.mjs';

const xml = resolve(process.argv[2] ?? 'sample.xml');
const xslt = resolve(process.argv[3] ?? 'sample.xsl');
try {
  const start = performance.now();
  const engine = await createParser(dirname(xml));
  const output = engine.transformFiles(xml, xslt);
  console.log(JSON.stringify({
    host: `Node ${process.version}`,
    execution: 'Saxon HE 10.9 in Ristretto WASM inside Node; no Java subprocess',
    xml, xslt, output,
    elapsedMs: Math.round(performance.now() - start),
  }, null, 2));
} catch (error) {
  console.error('XSLT transform failed:', error.payload ?? error.message ?? String(error));
  process.exitCode = 1;
}
