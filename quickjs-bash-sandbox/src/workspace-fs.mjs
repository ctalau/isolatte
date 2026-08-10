// Bridges just-bash's `IFileSystem` interface (see node_modules/just-bash/
// dist/fs/interface.d.ts) from *inside* the QuickJS guest to a single real
// directory on disk (the "workspace"), through synchronous host functions.
//
// This plays the same confinement role ReadWriteFs played in the previous
// (non-QuickJS-hosted) version of this experiment: every path the guest
// filesystem sees is resolved against the workspace root with `..`
// traversal clamped at that root, exactly like a chroot, both here (in the
// guest-side path arithmetic) and again in the host bridge functions
// (defense in depth -- a bug in one layer doesn't hand over the real
// filesystem).
//
// Binary data crosses the host/guest boundary via quickjs-emscripten's own
// `ArrayBuffer` marshaling (`context.newArrayBuffer`/`getArrayBuffer`), not
// through just-bash's own Buffer/fs shim (the one used by its optional
// `js-exec` feature) -- that shim was found to have real correctness bugs
// (see git history / the previous version of this README) around embedded
// NUL bytes and indexed access. quickjs-emscripten's ArrayBuffer transfer
// is a core, well-exercised part of the library and round-tripped every
// byte value correctly in testing here.
import { existsSync, mkdirSync, readdirSync, statSync, lstatSync, readFileSync, writeFileSync, appendFileSync, rmSync, cpSync, renameSync, chmodSync, symlinkSync, linkSync, readlinkSync, utimesSync } from "node:fs";
import path from "node:path";

/** Collapses `.`/`..` against a workspace root without ever escaping it (chroot-style clamp). */
function clampToWorkspace(root, virtualPath) {
  const parts = String(virtualPath).split("/").filter((p) => p !== "" && p !== ".");
  const stack = [];
  for (const part of parts) {
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  return { hostPath: path.join(root, ...stack), virtualPath: "/" + stack.join("/") };
}

function walkAllPaths(root, dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    out.push("/" + path.relative(root, full).split(path.sep).join("/"));
    if (entry.isDirectory()) walkAllPaths(root, full, out);
  }
}

/**
 * Registers `__wfs_*` host bridge functions on a QuickJS context, and
 * evaluates the guest-side `WorkspaceFs` class (implements IFileSystem)
 * that calls them. After this resolves, `new globalThis.WorkspaceFs()`
 * inside the guest is a filesystem scoped to `workspaceRoot`.
 */
export function installWorkspaceFs({ context, evalOrThrow }, workspaceRoot) {
  mkdirSync(workspaceRoot, { recursive: true });

  function real(virtualPath) {
    return clampToWorkspace(workspaceRoot, virtualPath).hostPath;
  }
  function toVirtual(hostPath) {
    const rel = path.relative(workspaceRoot, hostPath);
    if (rel.startsWith("..")) return "/"; // shouldn't happen; clamp defensively anyway
    return "/" + rel.split(path.sep).join("/");
  }
  function statHandle(st) {
    const obj = context.newObject();
    context.newNumber(st.isFile() ? 1 : 0).consume((h) => context.setProp(obj, "isFile", h));
    context.newNumber(st.isDirectory() ? 1 : 0).consume((h) => context.setProp(obj, "isDirectory", h));
    context.newNumber(st.isSymbolicLink() ? 1 : 0).consume((h) => context.setProp(obj, "isSymbolicLink", h));
    context.newNumber(st.mode).consume((h) => context.setProp(obj, "mode", h));
    context.newNumber(st.size).consume((h) => context.setProp(obj, "size", h));
    context.newNumber(st.mtimeMs).consume((h) => context.setProp(obj, "mtimeMs", h));
    return obj;
  }
  function bridge(name, fn) {
    context.newFunction(name, fn).consume((h) => context.setProp(context.global, name, h));
  }

  bridge("__wfs_exists", (pathHandle) => context.newNumber(existsSync(real(context.getString(pathHandle))) ? 1 : 0));

  bridge("__wfs_stat", (pathHandle) => statHandle(statSync(real(context.getString(pathHandle)))));
  bridge("__wfs_lstat", (pathHandle) => statHandle(lstatSync(real(context.getString(pathHandle)))));

  bridge("__wfs_readFileBuffer", (pathHandle) => {
    const buf = readFileSync(real(context.getString(pathHandle)));
    return context.newArrayBuffer(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
  });
  bridge("__wfs_writeFile", (pathHandle, bufferHandle) => {
    const lifetime = context.getArrayBuffer(bufferHandle);
    const bytes = lifetime.value.slice();
    lifetime.dispose();
    writeFileSync(real(context.getString(pathHandle)), Buffer.from(bytes));
  });
  bridge("__wfs_appendFile", (pathHandle, bufferHandle) => {
    const lifetime = context.getArrayBuffer(bufferHandle);
    const bytes = lifetime.value.slice();
    lifetime.dispose();
    appendFileSync(real(context.getString(pathHandle)), Buffer.from(bytes));
  });

  bridge("__wfs_mkdir", (pathHandle, recursiveHandle) => {
    mkdirSync(real(context.getString(pathHandle)), { recursive: !!context.dump(recursiveHandle) });
  });
  bridge("__wfs_readdir", (pathHandle) => {
    const names = readdirSync(real(context.getString(pathHandle)));
    const arr = context.newArray();
    names.forEach((name, i) => context.newString(name).consume((h) => context.setProp(arr, i, h)));
    return arr;
  });
  bridge("__wfs_rm", (pathHandle, recursiveHandle, forceHandle) => {
    rmSync(real(context.getString(pathHandle)), { recursive: !!context.dump(recursiveHandle), force: !!context.dump(forceHandle) });
  });
  bridge("__wfs_cp", (srcHandle, destHandle, recursiveHandle) => {
    cpSync(real(context.getString(srcHandle)), real(context.getString(destHandle)), { recursive: !!context.dump(recursiveHandle) });
  });
  bridge("__wfs_mv", (srcHandle, destHandle) => {
    renameSync(real(context.getString(srcHandle)), real(context.getString(destHandle)));
  });
  bridge("__wfs_chmod", (pathHandle, modeHandle) => {
    chmodSync(real(context.getString(pathHandle)), context.getNumber(modeHandle));
  });
  bridge("__wfs_symlink", (targetHandle, linkPathHandle) => {
    symlinkSync(real(context.getString(targetHandle)), real(context.getString(linkPathHandle)));
  });
  bridge("__wfs_link", (existingHandle, newHandle) => {
    linkSync(real(context.getString(existingHandle)), real(context.getString(newHandle)));
  });
  bridge("__wfs_readlink", (pathHandle) => context.newString(toVirtual(readlinkSync(real(context.getString(pathHandle))))));
  bridge("__wfs_realpath", (pathHandle) => {
    const { hostPath, virtualPath } = clampToWorkspace(workspaceRoot, context.getString(pathHandle));
    return context.newString(existsSync(hostPath) ? virtualPath : virtualPath);
  });
  bridge("__wfs_utimes", (pathHandle, mtimeMsHandle) => {
    const mtime = new Date(context.getNumber(mtimeMsHandle));
    utimesSync(real(context.getString(pathHandle)), mtime, mtime);
  });
  bridge("__wfs_getAllPaths", () => {
    const out = [];
    walkAllPaths(workspaceRoot, workspaceRoot, out);
    const arr = context.newArray();
    out.forEach((p, i) => context.newString(p).consume((h) => context.setProp(arr, i, h)));
    return arr;
  });

  const guestClassSource = `
    class WorkspaceFs {
      resolvePath(base, p) {
        const parts = (p.startsWith("/") ? p : base + "/" + p).split("/").filter((x) => x !== "" && x !== ".");
        const stack = [];
        for (const part of parts) { if (part === "..") stack.pop(); else stack.push(part); }
        return "/" + stack.join("/");
      }
      async readFile(path, options) {
        const bytes = new Uint8Array(globalThis.__wfs_readFileBuffer(path));
        const encoding = (options && options.encoding) || (typeof options === "string" ? options : "utf8");
        return new TextDecoder(encoding === "binary" ? "latin1" : encoding).decode(bytes);
      }
      async readFileBuffer(path) { return new Uint8Array(globalThis.__wfs_readFileBuffer(path)); }
      async readFileBytes(path) {
        const bytes = new Uint8Array(globalThis.__wfs_readFileBuffer(path));
        let s = "";
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        return s;
      }
      async writeFile(path, content, options) {
        const bytes = content instanceof Uint8Array ? content : new TextEncoder().encode(String(content));
        globalThis.__wfs_writeFile(path, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
      }
      async appendFile(path, content) {
        const bytes = content instanceof Uint8Array ? content : new TextEncoder().encode(String(content));
        globalThis.__wfs_appendFile(path, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
      }
      async exists(path) { return !!globalThis.__wfs_exists(path); }
      async stat(path) { const r = globalThis.__wfs_stat(path); return { ...r, mtime: new Date(r.mtimeMs) }; }
      async lstat(path) { const r = globalThis.__wfs_lstat(path); return { ...r, mtime: new Date(r.mtimeMs) }; }
      async mkdir(path, options) { globalThis.__wfs_mkdir(path, !!(options && options.recursive)); }
      async readdir(path) { return Array.from(globalThis.__wfs_readdir(path)); }
      async rm(path, options) { globalThis.__wfs_rm(path, !!(options && options.recursive), !!(options && options.force)); }
      async cp(src, dest, options) { globalThis.__wfs_cp(src, dest, !!(options && options.recursive)); }
      async mv(src, dest) { globalThis.__wfs_mv(src, dest); }
      async chmod(path, mode) { globalThis.__wfs_chmod(path, mode); }
      async symlink(target, linkPath) { globalThis.__wfs_symlink(target, linkPath); }
      async link(existingPath, newPath) { globalThis.__wfs_link(existingPath, newPath); }
      async readlink(path) { return globalThis.__wfs_readlink(path); }
      async realpath(path) { return globalThis.__wfs_realpath(path); }
      async utimes(path, atime, mtime) { globalThis.__wfs_utimes(path, mtime instanceof Date ? mtime.getTime() : mtime); }
      getAllPaths() { return Array.from(globalThis.__wfs_getAllPaths()); }
    }
    globalThis.WorkspaceFs = WorkspaceFs;
  `;
  evalOrThrow(context, guestClassSource, "workspace-fs-guest.js", { type: "global" }).dispose();
}
