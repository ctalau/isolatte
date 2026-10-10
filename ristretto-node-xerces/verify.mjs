import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Fail if runtime setup attempts to fall back to an external Java executable.
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  childProcess[name] = () => { throw new Error(`Runtime attempted child_process.${name}`); };
}
syncBuiltinESMExports();

const root = dirname(fileURLToPath(import.meta.url));
const { createParser } = await import('./host.mjs');
const parser = await createParser(root);
const valid = parser.parseFile(resolve(root, 'sample.xml'));
assert.equal(valid.parser, 'org.apache.xerces.parsers.DOMParser');
assert.equal(valid.xercesVersion, 'Xerces-J 2.12.2');
assert.equal(valid.root, 'catalog');
assert.equal(valid.namespace, 'urn:example:catalog');
assert.equal(valid.elementCount, 5);
assert.equal(valid.text, 'Ristretto & Xerces — caféNode.js JVM');
console.log('PASS: external Xerces-J parsed a real UTF-8 XML file, namespaces, and entities.');

function errorText(error) {
  return String(error.payload ?? error.message ?? error);
}
assert.throws(() => parser.parseFile(resolve(root, 'malformed.xml')), (error) => {
  assert.match(errorText(error), /SAXParseException/);
  return true;
});
console.log('PASS: malformed XML returned a Xerces SAXParseException to Node.');
assert.throws(() => parser.parseFile(resolve(root, 'missing.xml')), (error) => {
  assert.match(errorText(error), /FileNotFoundException/);
  return true;
});
console.log('PASS: missing XML returned FileNotFoundException to Node.');
assert.deepEqual(parser.parseFile(resolve(root, 'sample.xml')), valid);
console.log('PASS: component remained usable after errors; all subprocess APIs were disabled.');

const probe = parser.probe();
for (const [name, passed] of Object.entries(probe)) assert.equal(passed, true, name);
console.log('PASS: Java I/O and NIO writes, host files/environment, subprocesses and native library loading were denied.');
console.log('LIMIT: Java can read mounted runtime files; class loading and Java I/O share WASI descriptors.');
const policy = parser.policy();
assert.throws(() => policy.imports['wasi:http/outgoing-handler'].handle({}), error => error.tag === 'http-request-denied');
for (const method of policy.deniedFilesystemOperations) {
  assert.throws(() => policy.filesystem.types.Descriptor.prototype[method](), error => error === 'read-only');
}
assert.throws(() => parser.parseFile('/etc/passwd'), /configured input directory/);
assert.ok(parser.stats().wasiCalls.length > 0, 'WASI call auditing is active');
console.log('PASS: HTTP, all twelve filesystem mutators, and input directory escape denied.');
assert.throws(() => parser.parseFile(resolve(root, 'external-entity.xml')), error => {
  assert.match(errorText(error), /DOCTYPE is disallowed/);
  return true;
});
console.log('PASS: XML DOCTYPE/external entity expansion denied.');
await assert.rejects(createParser(root, { omitInterface: 'wasi:http/outgoing-handler' }));
console.log('PASS: omitting a linked HTTP interface fails instantiation even though parsing never calls HTTP.');
const tinyQuota = await createParser(root, { maxInputBytes: 1 });
assert.throws(() => tinyQuota.parseFile(resolve(root, 'sample.xml')), /Input quota exceeded/);
console.log('PASS: input quota enforced before executing Java.');
const withoutFilesystem = await createParser(root, { noFilesystem: true });
assert.throws(() => withoutFilesystem.parseFile(resolve(root, 'sample.xml')));
console.log('PASS: denying all filesystem preopens prevents JVM boot, confirming the current class loader dependency.');
