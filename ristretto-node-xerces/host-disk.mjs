import { readFileSync, mkdirSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cli, http } from '@bytecodealliance/preview2-shim';
import { WASIShim } from '@bytecodealliance/preview2-shim/instantiation';
import { instantiate } from './generated/xerces.js';

const root = dirname(fileURLToPath(import.meta.url));

/** Direct Node disk mounts, without preloading the JDK, JARs, or XML into memory. */
export async function createParser(inputDirectory = root) {
  inputDirectory = resolve(inputDirectory);
  const temporaryDirectory = resolve(root, 'target/tmp');
  mkdirSync(temporaryDirectory, { recursive: true });
  cli._setCwd('/input');
  const shim = new WASIShim({
    http: { ...http, outgoingHandler: { handle() { throw { tag: 'http-request-denied' }; } } },
    sandbox: {
      preopens: {
        '/jdk': resolve(root, 'vendor/runtime'),
        '/app': root,
        '/input': inputDirectory,
        '/tmp': temporaryDirectory,
      },
      env: {},
      args: ['ristretto-node-xerces'],
      enableNetwork: false,
    },
  });
  const component = await instantiate(
    (name) => WebAssembly.compile(readFileSync(resolve(root, 'generated', name))),
    {
      ...shim.getImportObject(),
      ...shim.getImportObject({ asVersion: '0.2.12' }),
    },
  );
  return {
    parseFile(file) {
      const absolute = resolve(file);
      if (dirname(absolute) !== inputDirectory) {
        throw new Error('XML file must be inside the configured input directory.');
      }
      return JSON.parse(component.parse(`/input/${basename(absolute)}`));
    },
  };
}
