// A development reference runner. This intentionally launches the real JVM.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { delimiter, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = fileURLToPath(new URL('.', import.meta.url));
const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin', 'java') : 'java';
try {
  const classpath = readFileSync(new URL('./target/classpath.txt', import.meta.url), 'utf8').trim();
  const paths = [process.argv[2] ?? new URL('./sample.xsl', import.meta.url),
    process.argv[3] ?? new URL('./sample.xml', import.meta.url)];
  const inputs = paths.map(path => new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(path)));
  const result = spawnSync(java, ['-Dfile.encoding=UTF-8', '-cp',
    join(directory, 'target/classes') + delimiter + classpath, 'org.isolatte.TransformXml', ...inputs],
    { cwd: directory, encoding: 'utf8', timeout: 20000 });
  if (result.error) throw result.error;
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exitCode = result.status ?? 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
