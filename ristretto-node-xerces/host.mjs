import { readFileSync, readdirSync, realpathSync, openSync, closeSync, fstatSync, readSync, constants } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { instantiate } from './generated/xerces.js';
import { enforceReadOnlyFilesystem, explicitImports, installAudit } from './host-policy.mjs';

const root = dirname(fileURLToPath(import.meta.url));
// Use the shim's in-memory implementation in Node, avoiding worker IPC for every
// small JImage read. The dependency is pinned because this is an internal entry point.
const memoryWasi = await import(new URL(
  '../browser/index.js', import.meta.resolve('@bytecodealliance/preview2-shim'),
));
const { cli, filesystem } = memoryWasi;
function directory(entries = {}) { return { dir: Object.assign(Object.create(null), entries) }; }
function loadFile(path) { return { source: new Uint8Array(readFileSync(path)) }; }
function loadDirectory(path) {
  const result = directory();
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = resolve(path, entry.name);
    result.dir[entry.name] = entry.isDirectory() ? loadDirectory(child) : loadFile(child);
  }
  return result;
}

const deniedFilesystemOperations = enforceReadOnlyFilesystem(filesystem);

function filesystemStats(tree, path = '') {
  const files = [];
  function visit(entry, path) {
    if (entry.dir) for (const [name, child] of Object.entries(entry.dir)) visit(child, `${path}/${name}`);
    else files.push({ path, bytes: entry.source.byteLength });
  }
  visit(tree, path);
  return { fileCount: files.length, bytes: files.reduce((sum, file) => sum + file.bytes, 0), files };
}

/** Instantiate Ristretto in this Node process with files loaded into an in-memory WASI filesystem. */
export async function createParser(inputDirectory = root, options = {}) {
  inputDirectory = realpathSync(resolve(inputDirectory));
  const maxInputBytes = options.maxInputBytes ?? 8 * 1024 * 1024;
  const maxOutputBytes = options.maxOutputBytes ?? 1024 * 1024;
  const audit = installAudit();
  const memories = new Set();
  const input = directory();
  const tree = directory({
    jdk: directory({
      release: loadFile(resolve(root, 'vendor/runtime/release')),
      lib: directory({
        modules: loadFile(resolve(root, 'vendor/runtime/lib/modules')),
        'tzdb.dat': loadFile(resolve(root, 'vendor/runtime/lib/tzdb.dat')),
      }),
      conf: loadDirectory(resolve(root, 'vendor/runtime/conf')),
    }),
    app: directory({
      classes: loadDirectory(resolve(root, 'classes')),
      vendor: directory({
        'xercesImpl-2.12.2.jar': loadFile(resolve(root, 'vendor/xercesImpl-2.12.2.jar')),
        'xml-apis-1.4.01.jar': loadFile(resolve(root, 'vendor/xml-apis-1.4.01.jar')),
        'Saxon-HE-10.9.jar': loadFile(resolve(root, 'vendor/Saxon-HE-10.9.jar')),
      }),
    }),
    input,
    tmp: directory(),
  });
  filesystem._setFileData(tree);
  filesystem._setPreopens({ '/': tree });
  cli._setCwd('/input');
  cli._setEnv({});
  cli._setArgs(['ristretto-node-xerces']);
  cli._setStdin({ blockingRead() { throw { tag: 'closed' }; } });
  let outputBytes = 0;
  const output = (stream) => ({ write(bytes) {
    outputBytes += bytes.byteLength;
    if (outputBytes > maxOutputBytes) throw new Error('Guest output quota exceeded');
    stream.write(bytes);
  } });
  cli._setStdout(output(process.stdout));
  cli._setStderr(output(process.stderr));
  const imports = explicitImports(memoryWasi);
  if (options.noFilesystem) imports['wasi:filesystem/preopens'] = { getDirectories: () => [] };
  if (options.omitInterface) delete imports[options.omitInterface];
  const initialFilesystem = filesystemStats(tree);
  const beforeInstantiation = process.memoryUsage();
  const component = await instantiate(
    (name) => WebAssembly.compile(readFileSync(resolve(root, 'generated', name))),
    imports,
    async (module, imports) => {
      const instance = await WebAssembly.instantiate(module, imports);
      for (const value of Object.values(instance.exports)) if (value instanceof WebAssembly.Memory) memories.add(value);
      return instance;
    },
  );
  function inputPath(file) {
    const absolute = resolve(file);
    if (dirname(absolute) !== inputDirectory) {
      throw new Error('XML/XSLT file must be inside the configured input directory.');
    }
    return absolute;
  }
  function clearInputs() {
    for (const previous of Object.keys(input.dir)) delete input.dir[previous];
  }
  function copyInputFile(absolute, name) {
    try {
      // Linux reproduction: bind the containment check to the opened descriptor,
      // reject symlinks, and limit the selected file before copying its bytes.
      const descriptor = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const actual = realpathSync(`/proc/self/fd/${descriptor}`);
        if (dirname(actual) !== inputDirectory) throw new Error('Input file escaped the authorized directory');
        const stat = fstatSync(descriptor);
        if (!stat.isFile()) throw new Error('Input must be a regular file');
        if (stat.size > maxInputBytes) throw new Error('Input quota exceeded');
        // Bound allocation even if another process grows the file after fstat.
        const buffer = Buffer.alloc(stat.size + 1);
        let count = 0;
        while (count < buffer.byteLength) {
          const read = readSync(descriptor, buffer, count, buffer.byteLength - count, null);
          if (read === 0) break;
          count += read;
        }
        if (count > stat.size) throw new Error('Input changed while being read');
        input.dir[name] = { source: new Uint8Array(buffer.subarray(0, count)) };
      } finally { closeSync(descriptor); }
    }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      delete input.dir[name]; // Let Java produce FileNotFoundException for a missing file.
    }
  }
  return {
    transformFiles(xmlFile, xsltFile) {
      const xml = inputPath(xmlFile);
      const xslt = inputPath(xsltFile);
      clearInputs();
      // Fixed distinct guest names also allow transforming a file against itself.
      copyInputFile(xml, 'document.xml');
      copyInputFile(xslt, 'stylesheet.xsl');
      outputBytes = 0;
      audit.setPhase(options.phase ?? 'transform');
      return component.transform('/input/document.xml', '/input/stylesheet.xsl');
    },
    parseFile(file) {
      const absolute = inputPath(file);
      const name = basename(absolute);
      clearInputs();
      copyInputFile(absolute, name);
      // Java reads the Node-supplied file through FileInputStream/WASI.
      outputBytes = 0;
      audit.setPhase(options.phase ?? 'parse');
      return JSON.parse(component.parse(`/input/${name}`));
    },
    probe() {
      outputBytes = 0;
      audit.setPhase('java-security-probe');
      return JSON.parse(component.probe());
    },
    stats() {
      return {
        initialFilesystem,
        currentFilesystem: filesystemStats(tree),
        wasmMemories: [...memories].map((memory) => ({ bytes: memory.buffer.byteLength })),
        beforeInstantiation,
        currentProcessMemory: process.memoryUsage(),
        quotas: { maxInputBytes, maxOutputBytes, filesystemWrites: false },
        wasiCalls: audit.snapshot(),
      };
    },
    policy() { return { imports, deniedFilesystemOperations, filesystem }; },
  };
}
