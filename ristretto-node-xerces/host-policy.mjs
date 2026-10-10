/** Explicit capabilities for this read-only XML experiment, not a general WASI sandbox. */
export function enforceReadOnlyFilesystem(filesystem) {
  const prototype = filesystem.types.Descriptor.prototype;
  const denied = [
    'writeViaStream', 'appendViaStream', 'write', 'setSize', 'setTimes',
    'setTimesAt', 'createDirectoryAt', 'linkAt', 'renameAt', 'symlinkAt',
    'unlinkFileAt', 'removeDirectoryAt',
  ];
  for (const method of denied) prototype[method] = () => { throw 'read-only'; };
  const openAt = prototype.openAt;
  const statAt = prototype.statAt;
  prototype.openAt = function (pathFlags, path, openFlags, flags) {
    if (openFlags.create || openFlags.truncate || flags.write || flags.mutateDirectory) {
      throw 'read-only';
    }
    try { return openAt.call(this, pathFlags, path, openFlags, flags); }
    catch (error) {
      // Correct the stock shim's ENOTDIR for an absent intermediate directory.
      if (error === 'not-directory') {
        const segments = path.split('/');
        for (let count = 1; count < segments.length; count++) {
          try { statAt.call(this, pathFlags, segments.slice(0, count).join('/') || '.'); }
          catch (parentError) { if (parentError === 'no-entry') throw parentError; break; }
        }
      }
      throw error;
    }
  };
  prototype.getFlags = () => ({ read: true });
  prototype.readlinkAt = () => { throw 'invalid'; }; // All mounted entries are regular files.
  return denied;
}

export function explicitImports(wasi) {
  const { cli, clocks, filesystem, http, io, random } = wasi;
  // No filesystem fallback, ambient environment, sockets, process launcher, or native library bridge.
  // Interfaces still required by the linked component are present, with dangerous operations denied.
  return {
    'wasi:cli/environment': cli.environment,
    'wasi:cli/exit': cli.exit, // The memory implementation throws; it never calls process.exit().
    'wasi:cli/stderr': cli.stderr,
    'wasi:cli/stdin': cli.stdin,
    'wasi:cli/stdout': cli.stdout,
    'wasi:cli/terminal-input': cli.terminalInput,
    'wasi:cli/terminal-output': cli.terminalOutput,
    'wasi:cli/terminal-stderr': cli.terminalStderr,
    'wasi:cli/terminal-stdin': cli.terminalStdin,
    'wasi:cli/terminal-stdout': cli.terminalStdout,
    'wasi:clocks/monotonic-clock': clocks.monotonicClock,
    'wasi:clocks/wall-clock': clocks.wallClock,
    'wasi:filesystem/preopens': filesystem.preopens,
    'wasi:filesystem/types': filesystem.types,
    'wasi:http/outgoing-handler': { handle() { throw { tag: 'http-request-denied' }; } },
    'wasi:http/types': http.types,
    'wasi:io/error': io.error,
    'wasi:io/poll': io.poll,
    'wasi:io/streams': io.streams,
    'wasi:random/insecure-seed': random.insecureSeed,
    'wasi:random/random': random.random,
  };
}

export function installAudit() {
  const calls = new Map();
  let phase = 'instantiate';
  globalThis[Symbol.for('isolatte.wasi.audit')] = (label) => {
    if (typeof label !== 'string' || !label.includes('Instruction::CallInterface') || !label.includes('@ enter')) return;
    const match = label.match(/iface="([^"]+)", function="([^"]+)"/);
    if (!match) return;
    const key = `${phase}|${match[1]}|${match[2]}`;
    calls.set(key, (calls.get(key) ?? 0) + 1);
  };
  return {
    setPhase(next) { phase = next; },
    snapshot() {
      return [...calls].map(([key, count]) => {
        const [phase, interfaceName, operation] = key.split('|');
        return { phase, interface: interfaceName, operation, count };
      }).sort((a, b) => `${a.phase}${a.interface}${a.operation}`.localeCompare(`${b.phase}${b.interface}${b.operation}`));
    },
  };
}
