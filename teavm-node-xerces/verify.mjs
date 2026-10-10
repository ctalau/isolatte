import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = fileURLToPath(new URL('.', import.meta.url));
const temporary = mkdtempSync(join(directory, 'target', 'verify-'));
let checks = 0;
function run(path) {
  const result = spawnSync(process.execPath, ['run.mjs', path], {
    cwd: directory, encoding: 'utf8', timeout: 10000,
  });
  assert.ifError(result.error);
  return result;
}
function reject(path, message) {
  const result = run(path);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, message);
  checks++;
}
function fixture(name, contents) {
  const path = join(temporary, name);
  writeFileSync(path, contents);
  return path;
}
try {
  const sample = run('sample.xml');
  assert.equal(sample.status, 0, sample.stderr);
  assert.deepEqual(JSON.parse(sample.stdout), {
    parser: 'org.apache.xerces.parsers.SAXParser', xercesVersion: 'Xerces-J 2.12.2',
    root: 'catalog', namespace: 'urn:example:catalog', elementCount: 5,
    text: 'TeaVM & Xerces — caféNode.js',
  });
  checks++;
  const rich = run(fixture('rich.xml', '<p:root xmlns:p="urn:test">&quot;\\&#10;<![CDATA[😀 <tag>]]><p:child/></p:root>'));
  assert.equal(rich.status, 0, rich.stderr);
  assert.deepEqual(JSON.parse(rich.stdout), {
    parser: 'org.apache.xerces.parsers.SAXParser', xercesVersion: 'Xerces-J 2.12.2',
    root: 'p:root', namespace: 'urn:test', elementCount: 2, text: '"\\\n😀 <tag>',
  });
  checks++;
  reject('malformed.xml', /matching end-tag/);
  reject('external-entity.xml', /DOCTYPE is disallowed/);
  reject(fixture('dtd.xml', '<!DOCTYPE root SYSTEM "https://example.invalid/test.dtd"><root/>'), /DOCTYPE is disallowed/);
  reject(fixture('internal.xml', '<!DOCTYPE root [<!ENTITY x "text">]><root>&x;</root>'), /DOCTYPE is disallowed/);
  reject(fixture('empty.xml', ''), /Premature end of file/);
  reject(fixture('unbound.xml', '<p:root/>'), /prefix.*not bound/);
  reject(fixture('invalid-utf8.xml', Buffer.from([0xff])), /encoded data was not valid/);
  reject(join(temporary, 'missing.xml'), /ENOENT/);
  console.log(`PASS: ${checks} checks (valid XML, namespaces, Unicode, CDATA, escaping, malformed XML, DTD rejection, invalid UTF-8, missing file)`);
  console.log(`Node ${process.version}; generated JavaScript ${statSync(join(directory, 'target/javascript/parser.cjs')).size} bytes`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
