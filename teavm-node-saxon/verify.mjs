import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = fileURLToPath(new URL('.', import.meta.url));
const temporary = mkdtempSync(join(directory, 'target', 'verify-'));
const compareJvm = process.argv.includes('--jvm');
let checks = 0;
let compared = 0;
function run(script, stylesheet, xml) {
  const result = spawnSync(process.execPath, [script, stylesheet, xml], {
    cwd: directory, encoding: 'utf8', timeout: 20000, maxBuffer: 2 * 1024 * 1024,
  });
  assert.ifError(result.error);
  return result;
}
function fixture(name, contents) {
  const path = join(temporary, name);
  writeFileSync(path, contents);
  return path;
}
function stylesheet(body, output = 'text') {
  return `<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:map="http://www.w3.org/2005/xpath-functions/map"
    exclude-result-prefixes="xs map"><xsl:output method="${output}" omit-xml-declaration="yes"/>
    <xsl:template match="/">${body}</xsl:template></xsl:stylesheet>`;
}
function success(name, xsl, xml, expected) {
  const stylePath = fixture(`${name}.xsl`, xsl);
  const inputPath = fixture(`${name}.xml`, xml);
  const result = run('run.mjs', stylePath, inputPath);
  assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  assert.equal(result.stdout, expected, name);
  if (compareJvm) {
    const reference = run('reference.mjs', stylePath, inputPath);
    assert.equal(reference.status, 0, `${name}: ${reference.stderr}`);
    assert.equal(result.stdout, reference.stdout, `${name}: JVM comparison`);
    compared++;
  }
  console.log(`PASS ${name}`);
  checks++;
}
function failure(name, xsl, xml, message) {
  const result = run('run.mjs', fixture(`${name}.xsl`, xsl), fixture(`${name}.xml`, xml));
  assert.equal(result.status, 1, `${name}: ${result.stdout}${result.stderr}`);
  assert.equal(result.stdout, '', name);
  assert.match(result.stderr, message, name);
  console.log(`PASS ${name}`);
  checks++;
}
try {
  success('sample', readFileSync('sample.xsl', 'utf8'), readFileSync('sample.xml', 'utf8'),
    'CAFÉ & XML | TEAVM\nTotal: 20.00\n');
  success('xml-serialization', stylesheet('<out><xsl:value-of select="root/text"/></out>', 'xml'),
    '<root><text>&lt;tag&gt; &amp; café 😀</text></root>', '<out>&lt;tag&gt; &amp; café 😀</out>');
  success('templates-sort', `<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text"/><xsl:template match="/"><xsl:apply-templates select="root/n">
    <xsl:sort select="." data-type="number"/></xsl:apply-templates></xsl:template>
    <xsl:template match="n"><xsl:value-of select="."/><xsl:text>;</xsl:text></xsl:template></xsl:stylesheet>`,
    '<root><n>10</n><n>2</n><n>1</n></root>', '1;2;10;');
  success('grouping', stylesheet(`<xsl:for-each-group select="root/item" group-by="@kind">
    <xsl:value-of select="concat(current-grouping-key(), ':', count(current-group()), ';')"/>
    </xsl:for-each-group>`), '<root><item kind="a"/><item kind="b"/><item kind="a"/></root>', 'a:2;b:1;');
  success('maps-and-arrays', stylesheet(`<xsl:value-of select="map:get(map{'a': array{1,2,3}}, 'a')?2"/>`),
    '<root/>', '2');
  success('regex-unicode', stylesheet(`<xsl:value-of select="replace('café-42', '\\p{L}+', 'word')"/>`),
    '<root/>', 'word-42');
  success('normalization', stylesheet(`<xsl:value-of select="normalize-unicode('e&#x301;', 'NFC')"/>`),
    '<root/>', 'é');
  success('decimal-arithmetic', stylesheet(`<xsl:value-of select="xs:decimal('0.1') + xs:decimal('0.2')"/>`),
    '<root/>', '0.3');
  success('json', stylesheet(`<xsl:sequence select="map{'answer':42}"/>`, 'json'), '<root/>', '{"answer":42}');
  failure('malformed-xml', stylesheet('<xsl:text>ok</xsl:text>'), '<root>', /end|XML|document/i);
  failure('malformed-stylesheet', '<xsl:stylesheet', '<root/>', /XML|document|markup|terminate/i);
  failure('static-xpath-error', stylesheet('<xsl:value-of select="1 +"/>'), '<root/>', /expression|XPST0003|errors/i);
  failure('runtime-xslt-error', stylesheet('<xsl:value-of select="error()"/>'), '<root/>', /FOER0000|error/i);
  failure('input-doctype', stylesheet('<xsl:value-of select="."/>'),
    '<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root>&x;</root>', /DOCTYPE is disallowed/);
  failure('stylesheet-doctype', '<!DOCTYPE xsl:stylesheet [<!ENTITY x "text">]>' + stylesheet('<xsl:text>&x;</xsl:text>'),
    '<root/>', /DOCTYPE is disallowed/);
  failure('include-denied', `<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:include href="https://example.invalid/include.xsl"/></xsl:stylesheet>`, '<root/>', /External resource access denied/);
  failure('document-denied', stylesheet(`<xsl:value-of select="doc('file:///etc/passwd')"/>`),
    '<root/>', /External resource access denied/);
  failure('text-denied', stylesheet(`<xsl:value-of select="unparsed-text('file:///etc/passwd')"/>`),
    '<root/>', /External text access denied/);
  failure('collection-denied', stylesheet(`<xsl:value-of select="collection('file:///tmp')"/>`),
    '<root/>', /External collection access denied/);
  failure('secondary-output-denied', stylesheet(`<xsl:result-document href="file:///tmp/teavm-result.xml"><out/></xsl:result-document>`),
    '<root/>', /Secondary result documents denied/);
  failure('locale-collation-unavailable', stylesheet(`<xsl:value-of select="compare('a', 'b', 'http://saxon.sf.net/collation?lang=en')"/>`),
    '<root/>', /Unavailable in TeaVM experiment/);
  console.log(`PASS: ${checks} checks; ${compared} successful outputs compared with JVM Saxon`);
  console.log(`Node ${process.version}; generated JavaScript ${statSync('target/javascript/transform.cjs').size} bytes`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
