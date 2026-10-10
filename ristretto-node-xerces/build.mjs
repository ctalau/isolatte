import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { transpileBytes } from '@bytecodealliance/jco-transpile';

const root = dirname(fileURLToPath(import.meta.url));
const run = (command, args, options = {}) => execFileSync(command, args, {
  cwd: root, stdio: 'inherit', ...options,
});
mkdirSync(join(root, 'classes'), { recursive: true });
run(join(root, 'vendor/jdk21/bin/javac'), [
  '--release', '8', '-Xlint:-options', '-encoding', 'UTF-8',
  '-cp', 'vendor/xercesImpl-2.12.2.jar:vendor/xml-apis-1.4.01.jar',
  '-d', 'classes', 'java/ParseXml.java', 'java/ProbeSandbox.java',
]);
if (!process.argv.includes('--skip-rust')) {
  run('cargo', ['build', '--locked', '--target', 'wasm32-wasip2', '--release'], {
    env: {
      ...process.env,
      RUSTC_BOOTSTRAP: '1',
      CARGO_TARGET_WASM32_WASIP2_RUSTFLAGS: '-C link-arg=-zstack-size=8388608',
    },
  });
}
const { files } = await transpileBytes(
  readFileSync(join(root, 'target/wasm32-wasip2/release/ristretto_node_xerces.wasm')),
  {
    name: 'xerces',
    instantiation: 'async',
    asyncMode: 'sync',
    wasiShim: false,
    nodejsCompat: true,
    base64Cutoff: 0,
    emitTypescriptDeclarations: true,
  },
);
for (const [name, bytes] of Object.entries(files)) {
  const destination = join(root, 'generated', name);
  mkdirSync(dirname(destination), { recursive: true });
  // Observe actual component host-call entry points without logging their payloads.
  // This hook is for measurement; capability enforcement happens in host-policy.mjs.
  const output = name === 'xerces.js'
    ? new TextEncoder().encode(new TextDecoder().decode(bytes).replace(
        'const _debugLog = (...args) => {',
        "const _debugLog = (...args) => { globalThis[Symbol.for('isolatte.wasi.audit')]?.(args[0]);",
      ))
    : bytes;
  writeFileSync(destination, output);
}
console.log('Built Java bridge and Ristretto WebAssembly component.');
