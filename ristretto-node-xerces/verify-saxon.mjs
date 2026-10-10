import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync, copyFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  childProcess[name] = () => { throw new Error(`Runtime attempted child_process.${name}`); };
}
syncBuiltinESMExports();
const root = dirname(fileURLToPath(import.meta.url));
const directory = mkdtempSync(resolve(tmpdir(), 'ristretto-saxon-'));
const file = name => resolve(directory, name);
const errorText = error => String(error.payload ?? error.message ?? error);
const stylesheet = body => `<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">${body}</xsl:stylesheet>`;
try {
  for (const name of ['sample.xml', 'sample.xsl', 'malformed.xml', 'external-entity.xml']) {
    copyFileSync(resolve(root, name), file(name));
  }
  writeFileSync(file('invalid.xsl'), stylesheet('<xsl:template match="/"><xsl:unknown/></xsl:template>'));
  writeFileSync(file('include.xsl'), stylesheet('<xsl:include href="sample.xsl"/>'));
  writeFileSync(file('document.xsl'), stylesheet('<xsl:template match="/"><xsl:value-of select="document(\'sample.xml\')"/></xsl:template>'));
  writeFileSync(file('text.xsl'), stylesheet('<xsl:template match="/"><xsl:value-of select="unparsed-text(\'sample.xml\')"/></xsl:template>'));
  const { createParser } = await import('./host.mjs');
  const engine = await createParser(directory);
  const transform = (xml = 'sample.xml', xslt = 'sample.xsl') => engine.transformFiles(file(xml), file(xslt));
  const expected = 'b1: RISTRETTO & XERCES — CAFÉ\nb2: NODE.JS JVM\n';
  assert.equal(transform(), expected);
  console.log('PASS: Saxon HE transformed namespaced UTF-8 XML with XSLT 2.0 upper-case(), without subprocesses.');
  for (const [xml, xslt, pattern] of [
    ['malformed.xml', 'sample.xsl', /SAXParseException|XML parser/],
    ['sample.xml', 'invalid.xsl', /Transformer|XPathException/],
    ['missing.xml', 'sample.xsl', /FileNotFoundException/],
    ['sample.xml', 'missing.xsl', /FileNotFoundException/],
    ['external-entity.xml', 'sample.xsl', /DOCTYPE is disallowed/],
    ['sample.xml', 'external-entity.xml', /DOCTYPE is disallowed/],
    ['sample.xml', 'include.xsl', /Additional XSLT resources are disabled/],
    ['sample.xml', 'document.xsl', /Exception thrown by URIResolver/],
    ['sample.xml', 'text.xsl', /Additional XSLT resources are disabled/],
  ]) {
    assert.throws(() => transform(xml, xslt), error => {
      assert.match(errorText(error), pattern);
      return true;
    });
    console.log(`PASS: rejected ${xml} / ${xslt}.`);
  }
  assert.equal(transform(), expected);
  assert.throws(() => engine.transformFiles(file('sample.xml'), resolve(root, 'sample.xsl')), /configured input directory/);
  console.log('PASS: component remained usable after errors; stylesheet directory escape denied.');
  const tinyQuota = await createParser(directory, { maxInputBytes: 256 });
  assert.throws(() => tinyQuota.transformFiles(file('sample.xml'), file('sample.xsl')), /Input quota exceeded/);
  console.log('PASS: stylesheet input quota enforced before Java execution.');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
