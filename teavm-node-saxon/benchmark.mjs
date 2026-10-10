import { readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { join, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import assert from 'node:assert/strict';

const directory = fileURLToPath(new URL('.', import.meta.url));
const require = createRequire(import.meta.url);
if (process.argv[2] === '--worker') {
  const [xslPath, xmlPath, warmup, iterations, reuse] = process.argv.slice(3);
  const xsl = readFileSync(xslPath, 'utf8');
  const xml = readFileSync(xmlPath, 'utf8');
  const beforeLoad = performance.now();
  const { benchmark } = require('./target/javascript/transform.cjs');
  const moduleLoadMs = performance.now() - beforeLoad;
  const result = JSON.parse(await benchmark(xsl, xml, Number(warmup), Number(iterations), reuse === 'true'));
  console.log(JSON.stringify({ ...result, moduleLoadMs }));
} else {
  const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin/java') : 'java';
  const classpath = join(directory, 'target/classes') + delimiter + readFileSync(join(directory, 'target/classpath.txt'), 'utf8').trim();
  const scratch = join(directory, 'target/benchmark');
  mkdirSync(scratch, { recursive: true });
  const version = spawnSync(java, ['-version'], { encoding: 'utf8' });
  assert.ifError(version.error);
  assert.equal(version.status, 0, version.stderr);
  const report = { node: process.version, java: version.stderr.trim(), platform: process.platform, arch: process.arch,
    saxon: '12.10', teavm: '0.16.0',
    generatedBytes: statSync(join(directory, 'target/javascript/transform.cjs')).size, cold: [], warm: [] };
  function run(runtime, xsl, xml, warmup, iterations, reuse) {
    const args = [xsl, xml, String(warmup), String(iterations), String(reuse)];
    const command = runtime === 'node' ? process.execPath : java;
    const argv = runtime === 'node' ? [join(directory, 'benchmark.mjs'), '--worker', ...args]
      : ['-Dfile.encoding=UTF-8', '-cp', classpath, 'org.isolatte.BenchmarkMain', ...args];
    const before = performance.now();
    const result = spawnSync(command, argv, { cwd: directory, encoding: 'utf8', timeout: 180000, maxBuffer: 1024 * 1024 });
    const wallMs = performance.now() - before;
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    return { runtime, ...JSON.parse(result.stdout.trim()), wallMs };
  }
  function checkOutputs(a, b) {
    assert.equal(a.outputLength, b.outputLength);
    assert.equal(a.outputHash, b.outputHash);
  }
  const sampleXsl = join(directory, 'sample.xsl'), sampleXml = join(directory, 'sample.xml');
  for (let fork = 0; fork < 7; fork++) {
    const order = fork % 2 ? ['jvm', 'node'] : ['node', 'jvm'];
    const pair = order.map(runtime => ({ fork, ...run(runtime, sampleXsl, sampleXml, 0, 1, false) }));
    checkOutputs(...pair);
    report.cold.push(...pair);
    console.log(`Cold fork ${fork + 1}/7: ${pair.map(p => `${p.runtime} ${p.wallMs.toFixed(1)} ms`).join(', ')}`);
    writeFileSync(join(directory, 'results/benchmark.json'), JSON.stringify(report, null, 2) + '\n');
  }
  const aggregateXsl = join(scratch, 'aggregate.xsl');
  writeFileSync(aggregateXsl, `<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text"/><xsl:template match="/">
    <xsl:value-of select="count(catalog/book)"/><xsl:text>;</xsl:text>
    <xsl:for-each-group select="catalog/book" group-by="@category">
      <xsl:sort select="current-grouping-key()"/>
      <xsl:value-of select="concat(current-grouping-key(), ':', count(current-group()), ':', format-number(sum(current-group()/@price), '0.00'), ';')"/>
    </xsl:for-each-group></xsl:template></xsl:stylesheet>`);
  const workloads = [{ name: 'sample', xsl: sampleXsl, xml: sampleXml, warmup: 100, iterations: 150 }];
  for (const count of [1000, 10000]) {
    const xml = join(scratch, `books-${count}.xml`);
    writeFileSync(xml, '<catalog>' + Array.from({ length: count }, (_, i) =>
      `<book category="c${i % 10}" price="${(i % 100) + 0.5}"><title>Café book ${i}</title></book>`).join('') + '</catalog>');
    workloads.push({ name: `${count}-books`, xsl: aggregateXsl, xml, warmup: count === 1000 ? 30 : 15, iterations: count === 1000 ? 60 : 30 });
  }
  for (const workload of workloads) {
    for (const reuse of [false, true]) {
      for (let fork = 0; fork < 3; fork++) {
        const order = fork % 2 ? ['jvm', 'node'] : ['node', 'jvm'];
        const pair = order.map(runtime => ({ workload: workload.name, inputBytes: statSync(workload.xml).size, reuse, fork,
          ...run(runtime, workload.xsl, workload.xml, workload.warmup, workload.iterations, reuse) }));
        checkOutputs(...pair);
        report.warm.push(...pair);
        console.log(`${workload.name}, ${reuse ? 'cached stylesheet' : 'compile each call'}, fork ${fork + 1}/3: ${pair.map(p => `${p.runtime} median ${p.medianMs.toFixed(3)} ms`).join(', ')}`);
        writeFileSync(join(directory, 'results/benchmark.json'), JSON.stringify(report, null, 2) + '\n');
      }
    }
  }
}
