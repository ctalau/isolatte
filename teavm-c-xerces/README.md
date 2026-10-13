# Xerces on TeaVM's C backend, file reads jailed to one folder

Xerces-J 2.12.2 (DOM parser, XInclude on) compiled by **TeaVM 0.16.0 to C**, then by gcc to a native `target/xi` binary. No JVM at run time. All file reads that the program makes through `java.io` / `java.net.URL file:` go through a `VirtualFileSystem` that exposes **one host folder, read-only, as `/`**. XInclude (XML and text) works inside the folder, and every attempt to get out is refused.

## Run

Requirements: JDK 21, Maven 3.9+, gcc (measured with OpenJDK 21.0.12.1, Maven 3.9.11, gcc on Ubuntu 24.04, x86-64).

```sh
cd teavm-c-xerces
./build.sh      # TeaVM -> target/c/*.c -> gcc -O2 -> target/xi  (about 2 min, gcc is most of it)
./verify.sh     # 18 assertions: inside works, 8 escapes blocked, no-jail control, strace audit
./bench.sh      # small-file performance (N=300 processes, 5000 warm in-process parses)
target/xi [--no-jail] [--bench N] [--probe] /abs/path/to/folder file:///main.xml ...
```

`/abs/path/to/folder` is the jail root. Inside the program `file:///main.xml` means `<folder>/main.xml`.

```text
$ target/xi $PWD/sample/jail file:///main.xml file:///escape-dotdot.xml
== file:///main.xml
   OK <book ...><title>Inside the jail</title><chapter id="c1">Café — included from chapters/chapter1.xml</chapter>plain text included from chapters/notes.txt</book>
== file:///escape-dotdot.xml
   warning: Include operation failed, reverting to fallback. Resource error reading file as XML (href='../outside/secret.xml'). Reason: null
   FAILED org.xml.sax.SAXParseException: An 'include' failed, and no 'fallback' element was found.
```

(Non-ASCII is printed as `\uXXXX` on purpose: TeaVM's C console does not pass UTF-8 through, which I did not fix. The parsed text itself is correct.)

## What was needed to make Xerces build for C

TeaVM 0.16.0's C target compiled Xerces only after four fixes, none of which touch the Xerces jar (bytecode transformers and one small factory):

| Problem | Fix | Code |
| --- | --- | --- |
| Xerces' `ObjectFactory` loads classes by name (`ClassLoader.loadClass`, `SecurityManager`), which TeaVM's classlib lacks | Calls to `*.ObjectFactory.newInstance/findProviderClass` are redirected to a switch with direct `new` / class literals for the six classes Xerces actually asks for | [`XercesCompat`](src/main/java/org/isolatte/c/XercesCompat.java), [`Shims`](src/main/java/org/isolatte/c/Shims.java) |
| The XML Schema validator (pulled in by `XML11Configuration`) calls `XMLReaderFactory.createXMLReader` | Redirected to a method that throws: XSD loading is **not supported** | same |
| TeaVM's `java.net.URL` has only an XMLHttpRequest handler for http(s), which does not compile for C (`Int8Array.set is native`), and no `file:` handler. Xerces opens every entity through `URL.openConnection()` | `file:` handler that opens `java.io.FileInputStream` (so it goes through the jail); every other scheme gets a handler that throws; XHR handler body replaced | [`FileUrlHandlers`](src/main/java/org/isolatte/c/FileUrlHandlers.java), [`PlatformTransformer`](src/main/java/org/isolatte/c/PlatformTransformer.java) |
| Error messages need `ResourceBundle`s | XMLMessages, SAXMessages, XIncludeMessages, XPointerMessages, DOMMessages, DatatypeMessages registered in `META-INF/services/java.util.ResourceBundle` | [`src/main/resources`](src/main/resources/META-INF/services/java.util.ResourceBundle) |

## The jail

[`JailFileSystem`](src/main/java/org/isolatte/c/JailFileSystem.java) is installed with `VirtualFileSystemProvider.setInstance(...)` before anything touches `java.io`, wrapping TeaVM's own `CFileSystem` (the native file layer of the C backend). Every `java.io.File` / `FileInputStream` call in TeaVM's classlib resolves its path through `VirtualFileSystemProvider.getInstance().getFile(path)`, so this is the single choke point.

1. The path is normalized lexically; `..` stops at `/`.
2. It is mapped under the root, and **each component below the root is checked with `readlink(2)`: a path containing a symlink anywhere does not exist.** Symlinks are never followed, even ones that point inside the folder (stricter than necessary, but it means no host path outside the folder is ever handed to the OS).
3. Anything else gets a read-only wrapper: write/append accessors, `createFile`, `delete`, `mkdir` and `setReadOnly` all fail.
4. `user.dir` is `/`, `user.home` is `/` (see below), `http(s)` and all other URL schemes refuse to connect.

The root path itself is trusted configuration, used as given.

### Verification ([results/verification.txt](results/verification.txt))

18 of 18 assertions pass:

- XML and text XInclude inside the folder, including via `chapters/../`.
- Blocked, with Xerces' include-resource error: `../outside/secret.xml` (XML and text), absolute `file://<host path>/secret.xml` (XML and text), `file:///etc/passwd`, an XInclude through a directory symlink pointing out, one through a file symlink pointing out, and `http://`. `xi:fallback` is honoured. Parsing `file:///../outside/secret.xml` directly fails.
- **Control:** the same binary with `--no-jail` and the same documents includes the outside secret in all four cases it is tried, so the jail, not the test setup, is what blocks them.
- **strace audit:** `strace -f -e trace=openat,open,stat,newfstatat,lstat,access,readlink,readlinkat,statx,getdents64` over a jailed run that attempts the escapes. Every path the program passes to the OS is under the jail folder (`/etc/passwd` appears only as `<jail>/etc/passwd`). The only paths outside it are the dynamic loader's own startup files (`/etc/ld.so.cache`, `/etc/ld.so.preload`, `libc.so.6`), opened before `main`.

The audit found two leaks in my first attempts, both fixed: (a) using `realpath(3)` to resolve symlinks `lstat`s every component of the *unjailed* path, so `/etc/passwd` and the outside folder were stat'ed even though never opened, hence the `readlink` walk from the root instead; (b) TeaVM's `System` static initializer calls `getpwuid` for `user.home`, which makes glibc read `/etc/nsswitch.conf` and `/etc/passwd` before `main`; that method is replaced with a constant.

## Performance, small file

Input: `sample/jail/main.xml`, 230 bytes, two XIncludes (a 1-element XML file and a text file). x86-64 Linux VM, gcc `-O2`. Raw output: [results/benchmark.txt](results/benchmark.txt).

| Measure | TeaVM C, jailed | TeaVM C, no jail | HotSpot 21 + Xerces |
| --- | --- | --- | --- |
| Fresh process, start to exit (median of 300; `fork+exec /bin/true` alone is 1.15 ms) | **5.7 ms** (p95 7.8) | 5.7 ms (p95 8.1) | 188 ms (p95 226); 174 ms with `TieredStopAtLevel=1` |
| First parse inside the process | 1.8 ms | 1.2 ms | 126 ms (class loading + interpreter) |
| Warm parse, median of 5000 | 442 us (p95 1.35 ms) | 397 us (p95 1.24 ms) | 228 us (p95 0.85 ms) |

- A cold one-shot parse of a small file takes about **5.7 ms wall** as a native process, roughly **33x faster** than starting a JVM (188 ms). Most of the native time is process start plus TeaVM runtime/heap setup, not the parse (1.8 ms).
- The jail is **not measurable in process wall time** (5.71 vs 5.71 ms). In-process it costs about **+11% warm** (442 vs 397 us, about 45 us per parse; I did not profile it, but the added work is the `readlink` walk per path lookup) and +0.6 ms on the first parse.
- When one process parses many documents, warmed-up HotSpot is faster: TeaVM C is **about 1.9x slower** than HotSpot per warm parse here (442 vs 228 us, jailed).
- Caveats: one 230-byte document, one machine, a shared cloud VM (the p95 tails are noisy), the dynamic `-O2` binary. The static link did not work (see below).

## Assessment

**What worked.** Xerces + XInclude compiles to C and runs as a ~12 MB native binary. The folder jail is enforced at the one place TeaVM's `java.io` reads files, and an strace audit confirms the OS never sees a path outside the folder after startup. Escapes by `..`, absolute path, file or directory symlink, `/etc/passwd`, and http all fail, while the unjailed control shows they would otherwise succeed.

**What did not work / limits.**
- The C console is not UTF-8 transparent (non-ASCII `System.out` becomes `?`); the tree output escapes it instead.
- A fully static binary (`gcc -static`) segfaults at startup. I did not debug it, so ld.so/libc loading is still outside the jail (before `main`). An earlier benchmark that included "static" numbers was timing that crash; it was discarded and re-run.
- DTD-validating, XML Schema and XPointer-fragment parsing are not exercised. XSD loading is stubbed to throw. Only the non-validating XInclude path was tested.
- The jail is a *library-level* one: it covers `java.io` and `file:` URLs. Code reaching libc directly through `@Import` natives (or a bug in TeaVM's runtime) is not covered. A compromised/hostile program needs an OS-level layer (seccomp/Landlock/bwrap, see the other experiments in this repo) around it. A check-then-open race remains for a symlink swapped in by a concurrent process inside the folder between the `readlink` walk and `open`.
- Read-only: writes are refused by design, not tested for output files.
- Only Linux/x86-64 and one 230-byte file were measured. Error text is "Reason: null" for blocked includes, like in the HotSpot experiment.

**Next.** Fix the static link (so the whole process, loader included, only sees the jail and the binary needs no libc), add a Landlock ruleset for the OS-level belt-and-braces, and measure a few hundred KB of input to see whether the warm-parse gap to HotSpot widens.

**Honest opinion.** Yes, this can be made to work for the stated purpose, and it does for non-validating XInclude. The file-read restriction is cheap and sound for the `java.io` path. I would not call it a security boundary on its own.
