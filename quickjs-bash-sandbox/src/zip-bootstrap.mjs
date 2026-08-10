// JavaScript source injected into the QuickJS sandbox as `js-exec` bootstrap
// code (see BashSandbox's `enableZip` option). It defines a single global,
// `zipDirectoryToBase64(srcDir)`, that reads every file directly under
// `srcDir` (as seen through the sandboxed/workspace-scoped filesystem) and
// builds a plain, uncompressed ("store" method) ZIP archive entirely inside
// the QuickJS VM.
//
// Why "store" bytes as strings instead of Buffer/Uint8Array:
//
// Testing against just-bash 3.2.0 found that the Node-compat `Buffer` shim
// exposed inside js-exec does not support indexed byte access or bulk copies
// reliably: `buf[i]` reads back `undefined`/0 for every index, and
// `someUint8Array.set(bufferInstance, offset)` silently copies zeros instead
// of the source bytes. Both are needed to hand-assemble binary structures
// like ZIP headers. Separately, `fs.writeFileSync()` (and
// `fs.readFileSync(path, encoding)`) truncate at the first embedded 0x00
// byte, which a general-purpose file's bytes will very likely contain.
//
// What *does* work reliably: `fs.readFileSync(path)` (no encoding, returns a
// Buffer) preserves the full byte count including embedded NULs, and
// `Buffer.prototype.toString('latin1')` / `Buffer.from(str, 'latin1')` round
// -trip arbitrary bytes through a JS string with one character per byte
// (verified 0..255 round-trip in manual testing). So this module stays in
// "byte string" land (built with `String.fromCharCode` and `charCodeAt`)
// until the very last step, where the whole archive is converted to base64
// and returned as a string. Base64 has no embedded NULs, so it survives the
// worker/host stdout channel intact; the caller (BashSandbox.zipDirectory)
// decodes it and writes the real .zip file from trusted host code, sidestepping
// the writeFileSync truncation bug entirely.
export const ZIP_BOOTSTRAP = `
function __crc32(str) {
  let table = globalThis.__crc32table;
  if (!table) {
    table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      table[n] = c >>> 0;
    }
    globalThis.__crc32table = table;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < str.length; i++) crc = table[(crc ^ str.charCodeAt(i)) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
function __dosDateTime(d) {
  const time = ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((d.getSeconds() >> 1) & 0x1f);
  const date = (((d.getFullYear() - 1980) & 0x7f) << 9) | (((d.getMonth() + 1) & 0xf) << 5) | (d.getDate() & 0x1f);
  return { time, date };
}
function __s16(n) { return String.fromCharCode(n & 0xff, (n >> 8) & 0xff); }
function __s32(n) { return String.fromCharCode(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff); }

globalThis.zipDirectoryToBase64 = function (srcDir) {
  const names = fs.readdirSync(srcDir).sort();
  const now = new Date();
  const { time, date } = __dosDateTime(now);
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  let count = 0;
  for (const name of names) {
    const full = srcDir.replace(/\\/+$/, '') + '/' + name;
    const st = fs.statSync(full);
    if (!st.isFile) continue;
    const content = fs.readFileSync(full).toString('latin1');
    const crc = __crc32(content);
    const size = content.length;
    const localHeader =
      '\\x50\\x4b\\x03\\x04' + __s16(20) + __s16(0) + __s16(0) + __s16(time) + __s16(date) +
      __s32(crc) + __s32(size) + __s32(size) + __s16(name.length) + __s16(0);
    localParts.push(localHeader, name, content);
    const centralHeader =
      '\\x50\\x4b\\x01\\x02' + __s16(20) + __s16(20) + __s16(0) + __s16(0) + __s16(time) + __s16(date) +
      __s32(crc) + __s32(size) + __s32(size) + __s16(name.length) + __s16(0) + __s16(0) +
      __s16(0) + __s16(0) + __s32(0) + __s32(offset);
    centralParts.push(centralHeader, name);
    offset += localHeader.length + name.length + content.length;
    count++;
  }
  const centralStart = offset;
  const centralBlob = centralParts.join('');
  const eocd =
    '\\x50\\x4b\\x05\\x06' + __s16(0) + __s16(0) + __s16(count) + __s16(count) +
    __s32(centralBlob.length) + __s32(centralStart) + __s16(0);
  const zipStr = localParts.join('') + centralBlob + eocd;
  return { count, bytes: zipStr.length, base64: Buffer.from(zipStr, 'latin1').toString('base64') };
};
`;
