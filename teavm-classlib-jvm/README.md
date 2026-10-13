# TeaVM's class library on a JVM, jailed to one folder

This experiment runs a real OpenJDK 21 HotSpot JVM with **TeaVM's `java.io` implementation** in place of OpenJDK's. That is TeaVM 0.16.0's `org.teavm.classlib.java.io.T*` classes, renamed to `java.io.*` and patched into `java.base`. TeaVM's file classes are written against TeaVM's `VirtualFileSystem` interface. Here that interface is backed by a read-only file system whose `/` is one host folder. Xerces-J 2.12.2 then parses XML with XInclude: includes inside the folder work, and includes that point outside it fail.

**Result:** it works for `java.io`. `java.io.File` really is TeaVM's class (stack frames show `TFile.java`). Xerces resolves an XML and a text XInclude inside the folder. Three escape attempts all fail with Xerces' XInclude resource error: `../outside/secret.xml`, an absolute host `file://` URI, and a symlink pointing out of the folder. `xi:fallback` is honoured. On stock OpenJDK the same three files *do* include the outside file, so the jail is what blocks them. The JVM's own core (`java.lang`, `java.util`, `invoke`, `ref`, …) cannot be TeaVM's: HotSpot rejects those classes at startup.

See [verification](results/verification.txt), [run output](results/run.txt), the [static link check](results/link-check.txt) and the [per-package boot probe](results/package-probe.md).

**Second variant: the whole class library.** The open-source [miniJVM](https://github.com/digitalgust/miniJVM) runs the same demo with *all* of TeaVM's class library as its JRE, `java.lang` included, and the same jail. That takes a 37-line patch, 59 C natives and a build step that adapts TeaVM's classes to miniJVM. The results match, and NIO, processes and sockets are closed too. See [The whole class library, on miniJVM](#the-whole-class-library-on-minijvm).

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

## The whole class library, on miniJVM

HotSpot will not accept TeaVM's `java.lang`. So the second variant runs on an open-source JVM whose class library *can* be swapped: [miniJVM](https://github.com/digitalgust/miniJVM) (MIT, C, about 40,000 lines with interpreter, JIT, GC and JDWP). It ships its own small class library, and its C code expects a short, explicit list of fields and methods from it. This variant gives miniJVM **TeaVM 0.16.0's class library as its entire JRE**: `java.lang.Object`, `String`, `Class`, `Throwable`, `System`, `java.util`, `java.io`, `java.nio.file`, `java.net`, `java.text`, … xml-apis, Xerces and the demo load on top. No miniJVM or OpenJDK class library class is on the boot class path.

**Result:** it works. The same `XIncludeDemo` gives the same outcomes as the HotSpot variant: the include inside the jail works, the three escapes fail, and `xi:fallback` is used. Xerces needed no changes. The jail now also covers NIO, because TeaVM's `java.nio.file` is built on the same `VirtualFileSystem`. A [sandbox probe](src/demo/org/isolatte/demo/SandboxProbe.java) that tries the usual ways out is blocked on every one, while stock HotSpot allows them. [`minijvm-verify.sh`](minijvm-verify.sh) asserts 34 outcomes ([verification](results/minijvm-verification.txt), [run output](results/minijvm-run.txt)). The five documents take about 1.6 s including VM startup, against about 0.25 s for the HotSpot variant.

### Run

Requirements in addition to the above: a C compiler, CMake, git, and network access to GitHub on the first build.

```sh
cd teavm-classlib-jvm
./minijvm-build.sh    # fetch miniJVM @87c9808, patch, build; build the TeaVM boot jar
./minijvm-verify.sh   # XInclude demo + sandbox probe + smoke test, 34 checks
./minijvm-run.sh --jail work/sample/jail org.isolatte.demo.XIncludeDemo file:///main.xml
```

`minijvm-run.sh` starts `org.isolatte.guest.Boot`, which installs the jailed file system and a `file:` URL handler and then calls the main class. The jail folder is passed to the VM as an absolute path in `ISOLATTE_JAIL`: miniJVM changes into its own directory at startup.

### What it took

| Part | What | Code |
| --- | --- | --- |
| miniJVM patch | 37 changed lines in 7 files. It registers the TeaVM native table, routes native binding through an allowlist, and fixes four miniJVM issues this exposed (listed below). | [`minijvm.patch`](minijvm/minijvm.patch) |
| TeaVM natives (C) | 59 natives. `ClassInfo` as `Class.ci$*` (modifiers, names, component and array types, supertypes, enum constants, reflective arrays, allocation), `Object.getObjectClassInfo`, number and math helpers, console output, class path resources, `Boot.callMain`, and the 5 jail natives. | [`jni_teavm.c`](minijvm/jni_teavm.c) |
| Renaming | TeaVM's compiler rules (`T`-prefix substitution, `@Superclass`, `@Rename`, `@Remove`), plus one mapping for miniJVM: TeaVM's `ClassInfo`/`StringInfo` become `Class`/`String`. miniJVM creates the `Class` objects itself, so a `Class` is its own `ClassInfo`. | [`TeaVMRenamer`](src/main/java/org/isolatte/minijvm/TeaVMRenamer.java) |
| Mixins (Java) | The fields miniJVM's C code reads (`String.value/count/offset/hash`, `Class.classHandle`, `Thread.stackFrame`, `StackTraceElement.parent`, `Reference.target`). TeaVM's `String` storage natives get bodies over those fields. TeaVM methods that miniJVM implements become miniJVM natives (`clone`, `wait`/`notify`, `arraycopy`, `identityHashCode`, `nanoTime`, `random`). `fillInStackTrace` reads miniJVM's frames. Also `forName`, `ClassLoader.loadClass`/`getResourceAsStream`, console output, and `getSecurityManager()` returning `null`. | [`src/minijvm-mixins`](src/minijvm-mixins) |
| `invokedynamic` | Removed at build time, as TeaVM's compiler does (TeaVM's `LambdaMetafactory` is a compiler intrinsic, while miniJVM runs bootstrap methods as Java). Lambdas become classes (354 of them), and string concatenation becomes `StringBuilder` chains. | [`IndyDesugar`](src/main/java/org/isolatte/minijvm/IndyDesugar.java) |
| Metadata | Unicode and CLDR tables: TeaVM's own generators (registrations from `JCLPlugin`) run at build time, and each metadata native becomes a method that decodes the serialized result. That is what TeaVM's compiler does too. | [`MetadataBaker`](src/main/java/org/isolatte/minijvm/MetadataBaker.java) |
| Assembly | Closure from the application classes and miniJVM's required classes (3,095 classes, 3.7 MB jar). Also the `System.out` field-to-method rewrite, `int.class` in TeaVM's box classes, nestmate-era private calls rewritten to `invokespecial`, compile-time metaprogramming stripped, and class version 50 without stack maps. | [`RuntimeBuilder`](src/main/java/org/isolatte/minijvm/RuntimeBuilder.java) |
| Guest support | A `VirtualFileSystem` over the jail natives, a `file:` URL handler on `java.io`, the `ResourceBundle` table, and metadata decoding. One Java SE class TeaVM lacks: `CharConversionException`. | [`src/vm-guest`](src/vm-guest/org/isolatte/guest), [`src/vm-gaps`](src/vm-gaps) |

### miniJVM issues found on the way (all in the patch)

- **`PATH_MAX` defined as 1024** before `<limits.h>` in `os_posix.c`. glibc's fortified `realpath` aborts with "buffer overflow detected" at startup on Ubuntu 24.04, even with miniJVM's own class library.
- **Abstract superinterface methods are not found** when a method reference names a class (JVMS 5.4.3.3). `invokevirtual AbstractCollection.size()` fails with a link error when `size()` is declared only in `Collection`, as it is in TeaVM's library.
- **Linkage errors use reflection exception classes**: `NoSuchMethodException`/`NoSuchFieldException` instead of `NoSuchMethodError`/`NoSuchFieldError`.
- **`new` of a missing class reports `OutOfMemoryError`** instead of `NoClassDefFoundError`.
- **No nestmates (Java 11+)**: calls to private methods via `invokevirtual` throw `IllegalAccessError`. This one is handled in the builder (rewritten to `invokespecial`), not patched.

### The native allowlist matters

miniJVM binds a native method by class and method name only. Its tables include file, socket, process (`Runtime.exec`) and library-loading (`System.loadLibrary0`) natives under miniJVM's own class names. A guest jar that declares, say, its own `org.mini.fs.InnerFile` with `native long openFile(byte[], byte[])` gets miniJVM's implementation. In a scratch build with the allowlist disabled, the probe's 11-line fixture class opened the host's `/etc/passwd`. With the patch, `find_native_method` only binds the 59 TeaVM natives and 25 named miniJVM natives (object, clock, math, stack trace). Everything else is reported as `[native] not bound: …` and fails with `NoSuchMethodError`. The probe asserts both.

### What the guest can reach

| Probe ([`SandboxProbe`](src/demo/org/isolatte/demo/SandboxProbe.java)) | stock HotSpot | miniJVM + TeaVM, jailed |
| --- | --- | --- |
| `java.io` read `/etc/passwd` | allowed | `FileNotFoundException` |
| `java.io` write `/tmp/…` | allowed | `FileNotFoundException` (read-only) |
| NIO `Files.readAllBytes(/etc/passwd)` | allowed | `NoSuchFileException` (TeaVM NIO, same jail) |
| NIO list `/` | host root | the jail folder (7 entries) |
| `ProcessBuilder`, `Runtime.exec` | allowed | `NoClassDefFoundError`, `NoSuchMethodError` |
| `Socket`, `http:` URL | attempted (connection refused) | `NoClassDefFoundError`; TeaVM's `http:` handler needs a browser's `XMLHttpRequest`, whose natives are not bound |
| `System.loadLibrary`, `sun.misc.Unsafe` | allowed | `NoSuchMethodError`, `ClassNotFoundException` |
| miniJVM's own file native via a guest class | n/a (`UnsatisfiedLinkError`) | blocked by the allowlist |
| `System.getenv("PATH")`, `user.home` | host values | `null`, `/` |
| class path resource `../../etc/passwd` | `null` | `null` (names with `..` are refused in C) |

Most rows are blocked because the capability does not exist in TeaVM's library, not because a policy said no. The guest's host interface is the native allowlist. Unlike the HotSpot variant, that list is short, and all of it is in [`jni_teavm.c`](minijvm/jni_teavm.c).

### Limits of the miniJVM variant

- **miniJVM is C.** Unlike a JVM written in Java, a bug in its interpreter, GC or class parser is memory-unsafe. Hostile bytecode is not verified (no verifier, frames are dropped), so this is not a boundary against malicious class files. The allowlist only closes the native-binding route.
- **Reflection metadata is missing**: `ci$reflection()` returns `null`, so `getMethods`/`getDeclaredFields`/`getConstructor` do not work. `Class.newInstance`, names, `isInstance`, enums and reflective arrays do. Weak references are strong.
- **Threads untested**: TeaVM's `Thread` is green-thread code and miniJVM's thread start natives are not bound. Single-threaded programs only.
- **Link warnings**: miniJVM links eagerly and prints `method not exist` for references to classes TeaVM lacks (Xerces' serialization hooks, the probes). 23 referenced classes are missing (`work/minijvm/boot.jar.missing.txt`).
- **Messages**: exceptions miniJVM raises itself (e.g. `ClassCastException`) carry no message.
- The jail's TOCTOU caveat is unchanged: the real path is checked, then opened. Pinned to one miniJVM commit and tested only on Linux x86-64.

## Assessment

Running TeaVM's `java.io` on HotSpot works, with ten small mixins. Plugging a folder-scoped file system into TeaVM's VFS gives the intended XInclude behaviour without changing Xerces or the application. The experiment also found two real issues in TeaVM's classlib: the sign-extending `FileInputStream.read()`, and `PrintStream` ignoring `autoFlush` for array writes.

As isolation, this is not enough. The jail covers one API surface while NIO, processes and the network remain open. Replacing more of the JRE runs into HotSpot's hard-wired core classes and OpenJDK's own boot code.

Next I would try one of these:
- Jail NIO through a custom `java.nio.file.spi.FileSystemProvider` set as the default, rather than replacing classes.
- Combine this with a process-level sandbox (the bwrap/nsjail experiments in this repo) for everything outside `java.io`.

The class-replacement approach is useful for testing TeaVM's classlib against real Java code on a JVM. I would not build a security boundary on it.

**The miniJVM variant** answers the question the HotSpot variant could not. Yes, TeaVM's whole class library can be a real JVM's entire JRE. It needs a JVM whose core-class contract is explicit (miniJVM's is about 30 fields and methods), a build step that does what TeaVM's compiler does (renaming, desugaring `invokedynamic`, baking metadata), and a small native layer. Xerces then runs XInclude unchanged. It fits better than expected because TeaVM 0.16 keeps string storage and class metadata behind natives, which map onto miniJVM's own `String` fields and `Class` objects.

What worked: everything the demo exercises, plus lambdas, string concatenation, `String.format` with CLDR data, Unicode case mapping, and stack traces from miniJVM's frames with TeaVM's source file names. The jail now covers NIO, and processes, sockets and native libraries are absent. Speed is about 6× slower than the HotSpot variant end to end.

What did not, or was not tried: reflection metadata, threads, weak references, and anything TeaVM's library lacks. It also surfaced five miniJVM issues; four are patched. The most important finding is that miniJVM binds natives by name, which lets guest code reach its file natives; the allowlist closes that.

As isolation it is much stronger than the HotSpot variant: the guest's host interface is one short allowlist. But miniJVM is a C interpreter without a bytecode verifier. I would trust it with trusted code that should stay confined, not with hostile class files, unless it runs inside the bwrap/seccomp sandbox from this repo.

Next I would:
- implement `ci$reflection()` from miniJVM's own field/method tables, so reflective code (Saxon, JAXP factories) works;
- bind TeaVM's `Thread` to miniJVM's native threads;
- upstream the four miniJVM fixes and an opt-in native allowlist;
- run the whole thing under the repo's bwrap/seccomp profile.

I think this is a viable way to run confined XML pipelines on a small embeddable VM.

References: TeaVM's renaming rule is `org.teavm.classlib.impl.ClasslibSubstitutionPolicy` in `teavm-classlib-0.16.0-sources.jar`; [JEP 261 (`--patch-module`)](https://openjdk.org/jeps/261).
