# TeaVM's class library on a JVM, jailed to one folder

This experiment runs a real OpenJDK 21 HotSpot JVM with **TeaVM's `java.io` implementation** in place of OpenJDK's. That is TeaVM 0.16.0's `org.teavm.classlib.java.io.T*` classes, renamed to `java.io.*` and patched into `java.base`. TeaVM's file classes are written against TeaVM's `VirtualFileSystem` interface. Here that interface is backed by a read-only file system whose `/` is one host folder. Xerces-J 2.12.2 then parses XML with XInclude: includes inside the folder work, and includes that point outside it fail.

**Result:** it works for `java.io`. `java.io.File` really is TeaVM's class (stack frames show `TFile.java`). Xerces resolves an XML and a text XInclude inside the folder. Three escape attempts all fail with Xerces' XInclude resource error: `../outside/secret.xml`, an absolute host `file://` URI, and a symlink pointing out of the folder. `xi:fallback` is honoured. On stock OpenJDK the same three files *do* include the outside file, so the jail is what blocks them. The JVM's own core (`java.lang`, `java.util`, `invoke`, `ref`, …) cannot be TeaVM's: HotSpot rejects those classes at startup.

See [verification](results/verification.txt), [run output](results/run.txt), the [static link check](results/link-check.txt) and the [per-package boot probe](results/package-probe.md).

**Second variant: the whole class library.** A small bytecode interpreter written for this experiment runs the same demo with *all* of TeaVM's class library as the JRE, `java.lang` included, and the same jail. The results match, and NIO, processes and sockets are closed too. It is about 15× slower. See [The whole class library, on a small JVM of our own](#the-whole-class-library-on-a-small-jvm-of-our-own).

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

## The whole class library, on a small JVM of our own

HotSpot will not accept TeaVM's `java.lang`. So the second variant ([`org.isolatte.vm`](src/main/java/org/isolatte/vm)) is a JVM that does not care: a bytecode interpreter of about 3,000 lines of Java. It runs as an ordinary program on HotSpot but has **no class library of its own**. Every guest class comes from TeaVM 0.16.0, renamed by TeaVM's rules: `java.lang.Object`, `String`, `Class`, `Throwable`, `System`, `java.util`, `java.io`, `java.nio.file`, `java.net`, `java.text`, … xml-apis, Xerces and the demo load on top. No OpenJDK class is on the guest class path.

**Result:** it works. The same `XIncludeDemo` gives the same outcomes as the HotSpot variant: the include inside the jail works, the three escapes fail, and `xi:fallback` is used. Xerces needed no changes. The jail now also covers NIO, because TeaVM's `java.nio.file` is built on the same `VirtualFileSystem`. A [sandbox probe](src/demo/org/isolatte/demo/SandboxProbe.java) that tries the usual ways out is blocked on every one, while stock HotSpot allows them. [`vm-verify.sh`](vm-verify.sh) asserts 34 outcomes ([verification](results/vm-verification.txt), [run output](results/vm-run.txt)). The cost is speed: the five documents take about 3.3–4.1 s against about 0.25 s for the HotSpot variant (≈21 M bytecodes, 403 classes).

### Why our own VM

No alternative JVM is packaged here: no JamVM, Avian, Cacao or GCJ. These VMs also hard-wire their own core-class layouts: JamVM through GNU Classpath's `VM*` classes, Avian through `types.def`. Porting either to TeaVM's `java.lang` would mean rewriting that coupling in C or C++.

TeaVM's library, by contrast, is written to leave storage to the backend, so a VM that owns the object layout fits well. `TString` has no character field, only natives (`charactersGet`, `initWithCharArray`, …). `Class` is a wrapper over a `ClassInfo` whose methods are all `@Intrinsified` natives. Unicode and CLDR tables come from natives filled in at compile time. Each of those is now one Java lambda in the VM.

### Run

```sh
cd teavm-classlib-jvm
./vm-build.sh         # VM (target/classes), guest support (work/vm-guest), gap classes, demo
./vm-verify.sh        # XInclude demo + sandbox probe + smoke test, 34 checks
./vm-run.sh --jail work/sample/jail --cp work/demo org.isolatte.demo.XIncludeDemo file:///main.xml
```

`VM_STATS=1` prints class and bytecode counts and every missing class or native. `VM_TRACE=1` logs unimplemented natives, failed `<clinit>`s and host exceptions turned into guest ones.

### How it works

| Part | What | Code |
| --- | --- | --- |
| Loader | For `java/x/Name` it reads `org/teavm/classlib/java/x/TName.class` and nothing else. It applies TeaVM's `ClassRefsRenamer` rules: rename every reference, `@Superclass("")` (`Object` has no parent), `@Rename` (it wins over a same-descriptor method, e.g. `TObject.equals0` over the bridge `equals`), `@Remove`. | [`Loader`](src/main/java/org/isolatte/vm/Loader.java) |
| Interpreter | All opcodes except `jsr`/`ret`. Values are boxed and `long`/`double` take one stack entry, so `dup2`/`pop2` decide by the value's type. Guest objects hold a field array plus a hidden host slot. Guest primitive arrays are host arrays. Host NPE, AIOOBE, `ArithmeticException` and `NegativeArraySizeException` become guest exceptions. Single-threaded, so monitors are no-ops. | [`VM`](src/main/java/org/isolatte/vm/VM.java) |
| `invokedynamic` | Lambdas (`LambdaMetafactory`, `altMetafactory`) become VM-made classes. String concatenation formats every value with the guest's own `String.valueOf`, so the text is TeaVM's. | [`Dynamic`](src/main/java/org/isolatte/vm/Dynamic.java) |
| Intrinsics | About 90 natives that TeaVM's compiler would generate, implemented in the VM: `String` storage, `ClassInfo`/`StringInfo`, `Object.identity`/`clone`, `System.arraycopy`, console output, `Math`/`Double`/`Float`. Also `Throwable.fillInStackTrace`, which builds TeaVM `StackTraceElement`s from the VM's frames, with TeaVM's source file names. | [`Intrinsics`](src/main/java/org/isolatte/vm/Intrinsics.java) |
| Metadata | Unicode case and digit tables, and CLDR (number and date formats): the VM reads the registrations from TeaVM's own `JCLPlugin.installMetadata` and runs TeaVM's host-side generators on first use. That is what TeaVM's compiler does at build time. The results become guest `StringResource`/`ResourceMap`/… objects. | [`Metadata`](src/main/java/org/isolatte/vm/Metadata.java) |
| Jail | Five natives (`attributes`, `list`, `length`, `lastModified`, `read`) take *virtual* paths. The VM normalizes them lexically, resolves them under the folder and canonicalizes them. A real path outside the folder does not exist. Read-only. | [`Jail`](src/main/java/org/isolatte/vm/Jail.java) |
| Guest support | Guest Java code compiled against OpenJDK's API but run against TeaVM's: a `VirtualFileSystem` over the jail natives, a `file:` URL handler on `java.io` (TeaVM's `URL` has none), and the `ResourceBundle` table. | [`src/vm-guest`](src/vm-guest/org/isolatte/guest) |

### What TeaVM's library needed from the VM, besides natives

| Gap | Why | Where |
| --- | --- | --- |
| `getstatic System.out/err/in` | TeaVM has `out()` methods; its compiler rewrites the field reads. The VM does the same. | `VM.systemStream` |
| `Class.forName` | TeaVM looks names up in the closed set of classes it compiled. Here classes load lazily from the guest class path. | `Intrinsics.classInfo` |
| `ClassLoader.loadClass` (added) and `getResourceAsStream` | TeaVM's `ClassLoader` has no `loadClass`. Its resources are embedded at compile time. Here they come from the guest class path, read-only. Xerces calls both. | `Intrinsics.patches` |
| `ResourceBundleImpl.createBundleMap` | Compile-time metaprogramming (`@Meta`) that builds the bundle table from `META-INF/services`. Replaced by a lazy guest map that finds a bundle class or `.properties`. | [`BundleMap`](src/vm-guest/org/isolatte/guest/BundleMap.java) |
| `System.getSecurityManager()` returns `null` | TeaVM returns a new, empty `SecurityManager`, and Xerces then calls `checkPackageAccess`, which TeaVM's lacks. Java SE returns `null` when none is installed. | `Intrinsics.patches` |
| `java.io.CharConversionException` | Missing from TeaVM's `java.io`. Xerces' `MalformedByteSequenceException` extends it. This is the only Java SE class added, compiled from 13 lines of source. | [`src/vm-gaps`](src/vm-gaps/java/io/CharConversionException.java) |

### What the guest can reach

| Probe ([`SandboxProbe`](src/demo/org/isolatte/demo/SandboxProbe.java)) | stock HotSpot | interpreter, jailed |
| --- | --- | --- |
| `java.io` read `/etc/passwd` | allowed | `FileNotFoundException` |
| `java.io` write `/tmp/…` | allowed | `FileNotFoundException` (read-only) |
| NIO `Files.readAllBytes(/etc/passwd)` | allowed | `NoSuchFileException` (TeaVM NIO, same jail) |
| NIO list `/` | host root (25 entries) | the jail folder (7 entries) |
| `ProcessBuilder`, `Runtime.exec` | allowed | `NoClassDefFoundError`, `NoSuchMethodError` |
| `Socket`, `http:` URL | attempted (connection refused) | `NoClassDefFoundError` (no `Socket`; TeaVM's `http:` needs a browser's `XMLHttpRequest`) |
| `System.loadLibrary`, `sun.misc.Unsafe` | allowed | `NoSuchMethodError`, `ClassNotFoundException` |
| `System.getenv("PATH")`, `user.home` | host values | `null`, `/` |
| class path resource `../../etc/passwd` | `null` | `null` |

Most rows are "blocked" because the capability does not exist in TeaVM's library or in the VM, not because a policy check said no. The guest's whole host interface is the VM's native list: console output, the five jail natives, class path resources, the clock, math, and TeaVM's metadata generators (which take no guest input). Guest values are host objects in a memory-safe host. So unverified or hostile bytecode can at worst cause a host `ClassCastException`, which ends the VM: a crash, not memory corruption.

Reviewing that interface turned up one real hole in my first version. `getResourceAsStream("../../../etc/passwd")` resolved against the class path *directories* and returned the host file. Guest-supplied names are now rejected if absolute or if they contain `.`, `..` or empty segments, and the probe asserts it.

### Limits of the interpreter variant

- **Speed:** roughly 15× slower than the HotSpot variant end to end (about 7 M bytecodes/s with boxed values). There is no JIT or caching beyond per-instruction link caches.
- **Single-threaded:** monitors are no-ops, `wait` is unsupported, and `Thread.start` is not implemented. TeaVM's own threads are green threads over JS/coroutines.
- **No reflection metadata:** `ClassInfo.reflection()` returns `null`, so `getMethods`/`getDeclaredFields`/`getConstructor` do not work. `Class.newInstance`, names, `isInstance`, enums and arrays do.
- **Partial JVM semantics:** no bytecode verification, no `ExceptionInInitializerError` (a failing `<clinit>` rethrows), no `MethodHandle`/`MethodType` constants or other bootstrap methods, and no access checks. Error classes TeaVM lacks (`UnsatisfiedLinkError`, …) are reported as `java.lang.Error` with the class name in the message.
- **No resource limits:** guest frames are capped at 3,000, but CPU and heap are the host's. Bugs in the VM's own Java code crash it, unless they are one of the four host exceptions it converts, which could also hide such a bug.
- **TeaVM library gaps** are the guest's gaps: no `File.toPath()`, `ProcessBuilder`, `Socket`, `loadLibrary`, … That is fine for this demo, and it is also why the probe is blocked. Other software will hit missing classes or methods sooner than on HotSpot.
- The jail's TOCTOU caveat is unchanged: the real path is checked, then opened.

## Assessment

Running TeaVM's `java.io` on HotSpot works, with ten small mixins. Plugging a folder-scoped file system into TeaVM's VFS gives the intended XInclude behaviour without changing Xerces or the application. The experiment also found two real issues in TeaVM's classlib: the sign-extending `FileInputStream.read()`, and `PrintStream` ignoring `autoFlush` for array writes.

As isolation, this is not enough. The jail covers one API surface while NIO, processes and the network remain open. Replacing more of the JRE runs into HotSpot's hard-wired core classes and OpenJDK's own boot code.

Next I would try one of these:
- Jail NIO through a custom `java.nio.file.spi.FileSystemProvider` set as the default, rather than replacing classes.
- Combine this with a process-level sandbox (the bwrap/nsjail experiments in this repo) for everything outside `java.io`.

The class-replacement approach is useful for testing TeaVM's classlib against real Java code on a JVM. I would not build a security boundary on it.

**The interpreter variant** answers the question the HotSpot variant could not. Yes, TeaVM's whole class library can be a JVM's entire JRE: a lazily loading interpreter needs about 90 natives, TeaVM's own metadata generators (31 registrations), the five adaptations and one missing exception class listed above. Xerces then runs XInclude unchanged. This fits better than expected because TeaVM 0.16 keeps object storage and class metadata behind natives.

What worked: everything the demo exercises, plus lambdas, string concatenation, `String.format` with CLDR data, Unicode case mapping, and guest stack traces with TeaVM's file names. The jail now covers NIO, and processes, sockets and native libraries are simply absent.

What did not, or was not tried: threads, reflection metadata, performance (about 15× slower), and anything TeaVM's library lacks.

As isolation it is much stronger than the HotSpot variant. The guest's host interface is a short native list that can be read in one sitting, which is where the one real escape I found, class path traversal, sat. But it is a research interpreter, not a hardened VM: it has no verifier, no resource limits, and a host process around it.

Next I would:
- add `ClassInfo.reflection()` from the ASM class nodes, so reflective code (Saxon, JAXP factories) works;
- add green threads on the interpreter loop (it already owns the frames);
- speed it up: unboxed int/long stacks, pre-decoded instructions;
- run it inside the bwrap/seccomp sandbox from this repo for defence in depth.

I think the variant is viable for running trusted-but-confined XML pipelines where 10–20× overhead is acceptable. To make it competitive, I would rather invest in TeaVM's own Wasm/C backends (see `teavm-node-saxon`), which AOT-compile the same library.

References: TeaVM's renaming rule is `org.teavm.classlib.impl.ClasslibSubstitutionPolicy` in `teavm-classlib-0.16.0-sources.jar`; [JEP 261 (`--patch-module`)](https://openjdk.org/jeps/261).
