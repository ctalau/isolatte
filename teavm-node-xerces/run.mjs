import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
try {
  const path = process.argv[2] ?? new URL('./sample.xml', import.meta.url);
  const xml = new TextDecoder('utf-8', { fatal: true }).decode(await readFile(path));
  const { main } = require('./target/javascript/parser.cjs');
  await new Promise((resolve, reject) => {
    main([xml], result => result instanceof Error ? reject(result) : resolve(result));
  });
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
