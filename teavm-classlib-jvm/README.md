# TeaVM's java.io on HotSpot, jailed to one folder

This experiment runs a real OpenJDK 21 HotSpot JVM with **TeaVM's `java.io` implementation** in place of OpenJDK's. That is TeaVM 0.16.0's `org.teavm.classlib.java.io.T*` classes, renamed to `java.io.*` and patched into `java.base`. TeaVM's file classes are written against TeaVM's `VirtualFileSystem` interface. Here that interface is backed by a read-only file system whose `/` is one host folder. Xerces-J 2.12.2 then parses XML with XInclude: includes inside the folder work, and includes that point outside it fail.

**Result:** it works for `java.io`. `java.io.File` really is TeaVM's class (stack frames show `TFile.java`). Xerces resolves an XML and a text XInclude inside the folder. Three escape attempts all fail with Xerces' XInclude resource error: `../outside/secret.xml`, an absolute host `file://` URI, and a symlink pointing out of the folder. `xi:fallback` is honoured. On stock OpenJDK the same three files *do* include the outside file, so the jail is what blocks them. The JVM's own core (`java.lang`, `java.util`, `invoke`, `ref`, …) cannot be TeaVM's: HotSpot rejects those classes at startup.

See [verification](results/verification.txt), [run output](results/run.txt), the [static link check](results/link-check.txt) and the [per-package boot probe](results/package-probe.md).

## Run

Requirements: JDK 21 (measured with Ubuntu OpenJDK 21.0.12.1), Maven 3.9+, Linux.

```sh
cd teavm-classlib-jvm
./build.sh            # overlay + mixins + link check + demo
./verify.sh           # runs ./run.sh and asserts 17 expected outcomes
./probe-packages.sh   # optional: which raw TeaVM packages HotSpot accepts at all
```

The jailed command line that `run.sh` uses:

```sh
java -Xshare:off \
  --patch-module java.base=work/overlay/java.base \
  -Xbootclasspath/a:xercesImpl-2.12.2.jar:work/bundles:work/demo \
  -Djdk.internal.io.vfs.root=work/sample/jail \
  org.isolatte.demo.XIncludeDemo file:///main.xml file:///escape-dotdot.xml ...
```

The demo ([`XIncludeDemo`](src/demo/org/isolatte/demo/XIncludeDemo.java)) is plain application code. It uses Xerces' `DOMParser` with `XIncludeAwareParserConfiguration` and knows nothing about the jail. Inside the JVM, `file:///main.xml` is `<jail>/main.xml`.

```text
== file:///main.xml
   OK <book ...><title>Inside the jail</title><chapter id="c1">Café — included from chapters/chapter1.xml</chapter>plain text included from chapters/notes.txt</book>
== file:///escape-dotdot.xml
   warning: Include operation failed, reverting to fallback. Resource error reading file as XML (href='../outside/secret.xml'). Reason: null
   FAILED org.xml.sax.SAXParseException: An 'include' failed, and no 'fallback' element was found.
```

## How it is built

| Step | What | Code |
| --- | --- | --- |
| Rename | TeaVM's own substitution rule (package prefix `org.teavm.classlib.`, `T` on the top-level simple name), applied to the bytecode with ASM. `org.teavm.runtime.fs.*` (the VFS API, from teavm-core) moves into the existing `jdk.internal.io` package, because HotSpot rejects packages that java.base does not already have if they load before the module system is up. TeaVM's private `UTF8Charset` maps to OpenJDK's `sun.nio.cs.UTF_8`; TeaVM's `System.getTempDir()` is redirected. | [`OverlayBuilder`](src/main/java/org/isolatte/overlay/OverlayBuilder.java) |
| Mixins | Small Java classes compiled against the renamed TeaVM classes, merged in with ASM. They add only what OpenJDK's remaining java.base code calls (`@MixinProvided` marks TeaVM members they only reference; `@MixinReplace` replaces one). | [`MixinMerger`](src/main/java/org/isolatte/overlay/MixinMerger.java), [`src/compat`](src/compat) |
| Link check | Resolves every member reference between the overlay, the rest of OpenJDK's java.base, and Xerces. It also checks that each mixin `native` has a libjava JNI symbol. | [`LinkChecker`](src/main/java/org/isolatte/overlay/LinkChecker.java) |
| Jail | `FolderFileSystem` implements TeaVM's `VirtualFileSystem`, selected by `-Djdk.internal.io.vfs.root`. It is installed from the first `java.io.File` the JDK creates, before `main`. | [`FolderFileSystem`](src/compat/jdk/internal/io/FolderFileSystem.java), [`VirtualFileSystemProvider`](src/compat/jdk/internal/io/VirtualFileSystemProvider.java) |
| Host access | No NIO: loading libnio itself goes through `java.io.File`. The jail reaches the host only through libjava's existing JNI natives. Metadata comes from OpenJDK's unpatched `UnixFileSystem`. Reads go through `RandomAccessFile.open0/readBytes0/seek0/length0`, bound by declaring them in the `RandomAccessFile` mixin. The bridge is package-private and registered SharedSecrets-style in unexported `jdk.internal.io`. | [`HostFiles`](src/compat/java/io/HostFiles.java), [`HostFileAccessor`](src/compat/java/io/HostFileAccessor.java) |

All 62 TeaVM `java.io` classes are used except `Console` and `Externalizable`, which stay OpenJDK's.

### What OpenJDK needed from TeaVM's java.io (the mixins)

| Gap | Symptom without it | Mixin |
| --- | --- | --- |
| `FileInputStream/FileOutputStream(FileDescriptor)` | VM init fails in `System.initPhase1` (stdin/stdout/stderr) | descriptor-backed accessor over libjava's `readBytes`/`writeBytes`, with an `fd` field for `initIDs` |
| TeaVM `PrintStream` honours `autoFlush` only in `write(int)` | `System.out`/`err` output stays in OpenJDK's 8 KiB `BufferedOutputStream` and is lost at exit | `write(byte[],int,int)` flushes when autoflushing |
| `SharedSecrets` accessors registered by OpenJDK's `PrintStream`, `PrintWriter`, `RandomAccessFile` static initializers | `Throwable.printStackTrace` → NPE in the uncaught-exception handler | registered from mixin static initializers |
| **TeaVM bug:** `FileInputStream.read()` returns the byte sign-extended, through a static shared buffer | byte `0xFF` reads as `-1` (EOF), `0x80` as `-128` | `read()` returns `b & 0xFF`, with a local buffer |
| `File.isInvalid/getPrefixLength/toPath`, `ByteArrayOutputStream.writeBytes`, `Writer(Writer)`, `PrintStream(String)`, `BufferedReader.lines()` (TeaVM's uses its internal stream impl) | `NoSuchMethodError` / `NoClassDefFoundError` when reached | direct implementations. `toPath()` throws: mapping to the host NIO file system would bypass the jail |

Remaining unresolved references (see the [link check](results/link-check.txt)) are in OpenJDK leftovers that are dead with this overlay (`File$TempDirectory`, `PrintStream$1`, `RandomAccessFile$2`). The exceptions are `LineNumberReader` (needs `BufferedReader.readLine(boolean, boolean[])`) and `Console`'s `ProxyingConsole`; neither is implemented.

### What the jail exposes

- `/` = the folder, **read-only**. Paths are normalized lexically (`..` stops at `/`), then the host path is canonicalized. Anything that resolves outside the folder, including via symlinks, does not exist.
- `${java.home}/lib`, read-only at its host path. OpenJDK reads its own runtime files through `java.io`, e.g. `TimeZone` loads `tzdb.dat` when `FileURLConnection` formats `Last-Modified` for a text XInclude.
- The *existence* (no contents, no listing) of `lib*.so` in `sun.boot.library.path`. `jdk.internal.loader.NativeLibraries` calls `File.exists()` before its native `dlopen`; without this, libnio cannot load and the boot layer fails.

The demo and Xerces go on `-Xbootclasspath/a`, which HotSpot reads natively. The normal class path does not work: the application class loader opens class-path entries through `java.io`, and its `CodeSource` setup reads `${java.home}/conf/security/java.security`, which is not exposed. Boot-class-path *resources* are also found through `java.io`. So Xerces' message bundles are compiled from its `.properties` into `ListResourceBundle` classes ([`BundleCompiler`](src/main/java/org/isolatte/overlay/BundleCompiler.java)), rather than exposing the jar.

## Replacing more than java.io

[`probe-packages.sh`](probe-packages.sh) patches each raw TeaVM package alone and boots a hello-world ([results](results/package-probe.md)):

- **Rejected by HotSpot itself:** `java.lang` ("Incompatible definition of java.lang.Object"), `java.lang.invoke`, `java.lang.ref`, `java.lang.reflect`, `java.security` (well-known class layout checks), and `java.lang.annotation` (circularity).
- **Break OpenJDK's boot code:** `java.util`, `java.util.concurrent`, `java.util.stream`, `java.nio`, `java.nio.charset`, `java.nio.file`, `java.net`.
- **Boot fine alone:** `java.math`, `java.text`, `java.util.regex`, `java.util.zip`, `java.util.jar`, `java.util.function`, `java.util.random`, `java.nio.channels`.

With `java.io` plus each of `java.math`, `java.util.regex`, `java.util.zip` or `java.util.jar`, the full XInclude demo still gives the expected results. `EXTRA_PACKAGES='java/math/ java/util/regex/ java/util/function/ java/util/random/ java/nio/channels/' ./build.sh` (296 classes) passes too. TeaVM's regex (`TPattern.java`) and `BigDecimal`/`BigInteger` gave OpenJDK's results on spot checks. Limits of the wider overlay:

- `java.text` fails at the first `SimpleDateFormat`: TeaVM's `DateFormatSymbols` needs `CLDRHelper`, which TeaVM generates at compile time.
- `java.util.zip` fails at the first `CRC32`: it needs jzlib, which is not in the classlib jar.
- The link checker reports 51–109 unresolved references for these wider sets.

## Limits

This is a feasibility port, not a sandbox.

- **Only `java.io` is jailed.** OpenJDK's `java.nio.file` still has full host access (`Files.isReadable(/etc/passwd)` is `true`), and processes can be started. `verify.sh` asserts both, as known gaps. URL schemes other than `file:` (`http:`, …) are untouched. TeaVM's `java.nio.file` is built on the same VFS, but it does not boot in place of OpenJDK's (see the probe), and OpenJDK's module patcher and `jrt:` use NIO during boot.
- **Read-only:** writes, creates and deletes fail. TeaVM's VFS accessor API uses `int` sizes, so files over 2 GiB are not supported.
- **TOCTOU:** confinement is checked on the canonical path, then libjava's `open` follows symlinks (no `O_NOFOLLOW`). Another host process swapping a path component for a symlink between check and open is not prevented.
- **Thread safety:** TeaVM's class library assumes one thread. Other `static` one-byte buffers remain (e.g. `FileOutputStream.write(int)`).
- `FileInputStream/FileOutputStream.getChannel()` throw `UnsupportedOperationException`. `FileNotFoundException`s carry no message (TeaVM's), hence Xerces' "Reason: null".
- `-Xshare:off` is passed explicitly: the CDS archive holds OpenJDK's classes (`--patch-module` disables it anyway). Only tested on Linux x86-64 with one JDK build. The JNI symbol names are JDK-21-specific.

## Assessment

Running TeaVM's `java.io` on HotSpot works, with ten small mixins. Plugging a folder-scoped file system into TeaVM's VFS gives the intended XInclude behaviour without changing Xerces or the application. The experiment also found two real issues in TeaVM's classlib: the sign-extending `FileInputStream.read()`, and `PrintStream` ignoring `autoFlush` for array writes.

As isolation, this is not enough. The jail covers one API surface while NIO, processes and the network remain open. Replacing more of the JRE runs into HotSpot's hard-wired core classes and OpenJDK's own boot code.

Next I would try one of these:
- Jail NIO through a custom `java.nio.file.spi.FileSystemProvider` set as the default, rather than replacing classes.
- Combine this with a process-level sandbox (the bwrap/nsjail experiments in this repo) for everything outside `java.io`.

The class-replacement approach is useful for testing TeaVM's classlib against real Java code on a JVM. I would not build a security boundary on it.

References: TeaVM's renaming rule is `org.teavm.classlib.impl.ClasslibSubstitutionPolicy` in `teavm-classlib-0.16.0-sources.jar`; [JEP 261 (`--patch-module`)](https://openjdk.org/jeps/261).
