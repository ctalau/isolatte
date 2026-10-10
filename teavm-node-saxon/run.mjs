import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
try {
  const paths = [process.argv[2] ?? new URL('./sample.xsl', import.meta.url),
    process.argv[3] ?? new URL('./sample.xml', import.meta.url)];
  const inputs = await Promise.all(paths.map(async path =>
    new TextDecoder('utf-8', { fatal: true }).decode(await readFile(path))));
  const { transform } = require('./target/javascript/transform.cjs');
  process.stdout.write(await transform(...inputs));
} catch (error) {
  console.error(error.stack);
  process.exitCode = 1;
}
