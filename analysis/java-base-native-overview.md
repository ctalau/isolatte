# OpenJDK `java.base` Native Code Analysis for JVM Sandboxing

## Executive Summary

The `java.base` module contains **201 C source files** with **~67,700 lines of code** across
6 platform directories. For a **Linux target** (share + unix + linux), the relevant subset is
**130 .c files** with **~30,000 lines of code**.

There are **492 unique JNI-exported native functions** for the Linux target, plus **~57 dynamically
registered methods** (via `RegisterNatives`), plus **~160 JVM_* functions** that are implemented
inside HotSpot and called from the native libraries.

For sandboxing purposes, the **critical surface** is approximately **~265 native functions** across
3 domains: file I/O (~136), networking (~106), and process/environment (~23+).

---

## 1. Source Code Structure

```
src/java.base/
├── share/native/       # Platform-independent (71 .c, ~18,400 LOC)
│   ├── libjava/        # Core Java runtime natives (49 .c, 5,568 LOC)
│   ├── libzip/         # ZIP/GZIP/zlib (20 .c, 12,351 LOC) — includes bundled zlib
│   ├── libjli/         # Java Launcher Infrastructure (7 .c, 4,650 LOC)
│   ├── libverify/      # Bytecode verifier (1 .c, 4,408 LOC)
│   ├── libnet/         # Network utilities (5 .c, 702 LOC)
│   ├── libfallbackLinker/ # Foreign Function Interface fallback (1 .c, 300 LOC)
│   ├── launcher/       # Launcher main (1 .c, 221 LOC)
│   ├── libnio/         # NIO shared (2 .c, 142 LOC)
│   ├── libsyslookup/   # System symbol lookup (1 .c, 37 LOC)
│   └── include/        # JNI headers (jni.h, jvmticmlr.h)
│
├── unix/native/        # Unix/POSIX-specific (29 .c, ~11,200 LOC)
│   ├── libjava/        # Unix Java runtime (15 .c, 4,425 LOC)
│   ├── libnet/         # Unix networking (7 .c, 4,496 LOC)
│   ├── libnio/         # Unix NIO channels/fs (16 .c, 4,476 LOC)
│   ├── libjli/         # Unix launcher (2 .c, 1,143 LOC)
│   ├── launcher/       # Unix launcher helpers (2 .c, 481 LOC)
│   ├── libjsig/        # Signal chaining (1 .c, 314 LOC)
│   └── jspawnhelper/   # Process spawn helper (1 .c, 189 LOC)
│
├── linux/native/       # Linux-specific (7 .c, ~1,122 LOC)
│   ├── libjava/        # Cgroup metrics (2 .c, 457 LOC)
│   ├── libnio/         # epoll, inotify, Linux fs (5 .c, 665 LOC)
│   └── libsimdsort/    # SIMD sort (not relevant)
│
├── windows/native/     # Windows-specific (not relevant for Linux sandbox)
├── macosx/native/      # macOS-specific (not relevant for Linux sandbox)
└── aix/native/         # AIX-specific (not relevant for Linux sandbox)
```

## 2. Native Libraries (Linux Target)

| Library | Files | LOC | Purpose | Sandbox Relevance |
|---------|-------|-----|---------|-------------------|
| **libjava** | 66 | ~10,450 | Core runtime: file I/O, process mgmt, system props, classloading | **CRITICAL** |
| **libnet** | 12 | ~5,200 | TCP/UDP sockets, DNS resolution, network interfaces | **CRITICAL** |
| **libnio** | 23 | ~5,280 | NIO channels, file dispatching, epoll, filesystem ops, inotify | **CRITICAL** |
| **libzip** | 20 | ~12,350 | ZIP/GZIP compression (includes bundled zlib) | LOW |
| **libjli** | 9 | ~5,800 | Java launcher infrastructure | LOW |
| **libverify** | 1 | ~4,400 | Bytecode verification | NONE |
| **libjsig** | 1 | ~314 | Signal chaining for native code | LOW |
| **libfallbackLinker** | 1 | ~300 | FFI fallback (uses libffi) | **HIGH** (escape hatch) |
| **libsyslookup** | 1 | ~37 | Symbol lookup for Foreign API | **HIGH** (escape hatch) |
| **launcher** | 3 | ~700 | `java` executable entry point | LOW |
| **jspawnhelper** | 1 | ~189 | Helper binary for process spawning | **HIGH** |

## 3. External Library Dependencies

### System libraries (Linux)
- **libdl** (`-ldl`): Dynamic library loading — used by libjava, libnet, libnio, libjimage, libsyslookup
- **libpthread** (`-lpthread`): Threading — used by libnio, libjli
- **libm** (`-lm`): Math — used by libsyslookup
- **libz** (`-lz`): Compression (or bundled zlib) — used by libzip, libjli

### System headers used (key ones for sandboxing)
- **File I/O**: `<fcntl.h>`, `<sys/stat.h>`, `<dirent.h>`, `<sys/statvfs.h>`, `<sys/mman.h>`, `<sys/sendfile.h>`
- **Networking**: `<sys/socket.h>`, `<netinet/in.h>`, `<netdb.h>`, `<arpa/inet.h>`, `<net/if.h>`, `<sys/epoll.h>`
- **Process**: `<unistd.h>` (fork/exec), `<sys/wait.h>`, `<signal.h>`, `<spawn.h>`
- **Environment**: `<stdlib.h>` (getenv), `<sys/utsname.h>`
- **Other**: `<dlfcn.h>` (dlopen/dlsym), `<sys/inotify.h>`, `<sys/xattr.h>`

### Optional external libraries
- **libffi**: Used by libfallbackLinker for Foreign Function & Memory API

## 4. JNI Native Function Inventory (Linux Target)

### Total counts
- **492 unique `Java_*` exported functions** (static JNI binding)
- **~57 dynamically registered methods** (via `JNINativeMethod` arrays + `RegisterNatives`)
- **~160 `JVM_*` functions** referenced (implemented in HotSpot, not in native libs)

### By domain

| Domain | Count | Sandbox Critical? |
|--------|-------|-------------------|
| File I/O (java.io + sun.nio.fs + sun.nio.ch file ops) | ~136 | **YES** |
| Network (java.net + sun.net + sun.nio.ch socket ops) | ~106 | **YES** |
| Process execution & management | ~19 | **YES** |
| Environment / System properties | ~9 | **YES** |
| NIO infrastructure (IOUtil, threads, selectors) | ~34 | PARTIAL |
| Foreign Function Interface (FFI) | ~29 | **YES** (escape hatch) |
| JVM internals (classloading, reflection, GC, threads) | ~107 | NO |
| ZIP/compression | ~27 | NO |
| Math/conversion (Float, Double) | ~4 | NO |
| Timezone | ~2 | NO |

---

## 5. Sandbox-Critical Native Functions — Detailed Breakdown

### 5.1 FILE SYSTEM ACCESS (~136 functions) — **HIGHEST PRIORITY**

These are spread across 3 layers of file I/O in Java:

#### 5.1.1 Classic I/O (`java.io.*`) — 48 functions
Implemented in: `share/native/libjava/` + `unix/native/libjava/`

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `FileInputStream` | 8 | open, read, readBytes, available, skip, length, position |
| `FileOutputStream` | 4 | open, write, writeBytes |
| `RandomAccessFile` | 10 | open, read, readBytes, write, writeBytes, seek, setLength, length, getFilePointer |
| `FileDescriptor` | 5 | close, sync, getAppend, getHandle, initIDs |
| `FileCleanable` | 1 | cleanupClose0 |
| `UnixFileSystem` | 16 | canonicalize, checkAccess, createDirectory, createFileExclusively, delete, getBooleanAttributes, getLastModifiedTime, getLength, getNameMax, getSpace, list, rename, setLastModifiedTime, setPermission, setReadOnly |
| `Console` | 1 | ttyStatus |
| `ObjectStreamClass` | 2 | hasStaticInitializer, initNative |

**Key C files:**
- `share/native/libjava/FileInputStream.c` — delegates to io_util
- `share/native/libjava/FileOutputStream.c` — delegates to io_util
- `share/native/libjava/RandomAccessFile.c` — delegates to io_util
- `unix/native/libjava/io_util_md.c` — **THE core file I/O implementation** (open, read, write via POSIX)
- `share/native/libjava/io_util.c` — shared I/O utilities
- `unix/native/libjava/UnixFileSystem_md.c` — all filesystem metadata operations
- `unix/native/libjava/canonicalize_md.c` — path canonicalization (realpath)

#### 5.1.2 NIO File Channels (`sun.nio.ch.*`) — 23 functions
Implemented in: `unix/native/libnio/ch/` + `linux/native/libnio/ch/`

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `UnixFileDispatcherImpl` | 18 | read, readv, write, writev, pread, pwrite, seek, size, truncate, force (fsync), lock, release, map (mmap), unmap, available, setDirect, close, allocationGranularity |
| `FileDispatcherImpl` | 3 | init, transferTo (sendfile), transferFrom |
| `FileKey` | 1 | init (fstat for inode) |

**Key C files:**
- `unix/native/libnio/ch/UnixFileDispatcherImpl.c` — NIO file channel I/O
- `linux/native/libnio/ch/FileDispatcherImpl.c` — Linux sendfile/copy_file_range

#### 5.1.3 NIO Filesystem (`sun.nio.fs.*`) — 65 functions
Implemented in: `unix/native/libnio/fs/` + `linux/native/libnio/fs/`

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `UnixNativeDispatcher` | 46 | open, openat, close, read, write, stat, lstat, fstat, fstatat, mkdir, rmdir, unlink, unlinkat, link, symlink, readlink, realpath, rename, renameat, chmod, fchmod, fchmodat, chown, fchown, lchown, access, getcwd, opendir, closedir, fdopendir, readdir, rewind, utimes, utimensat, futimens, statvfs, fgetxattr, fsetxattr, flistxattr, fremovexattr, mknod, getpwuid, getpwnam, getgrgid, getgrnam, strerror, getlinelen |
| `LinuxNativeDispatcher` | 5 | directCopy (copy_file_range), setmntent, getmntent, endmntent, posix_fadvise |
| `LinuxWatchService` | 7 | inotifyInit, inotifyAddWatch, inotifyRmWatch, poll, socketpair, configureBlocking, eventSize/Offsets |
| `UnixFileSystem` | 1 | bufferedCopy |

**Key C files:**
- `unix/native/libnio/fs/UnixNativeDispatcher.c` — **the biggest filesystem native file** (~1,500 LOC)
- `linux/native/libnio/fs/LinuxNativeDispatcher.c`
- `linux/native/libnio/fs/LinuxWatchService.c`

### 5.2 NETWORK ACCESS (~106 functions) — **HIGHEST PRIORITY**

#### 5.2.1 Classic Networking (`java.net.*`) — 25 functions
Implemented in: `share/native/libnet/` + `unix/native/libnet/`

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `InetAddress` | 3 | init, isIPv4Available, isIPv6Supported |
| `Inet4Address` | 1 | init |
| `Inet6Address` | 1 | init |
| `Inet4AddressImpl` | 4 | lookupAllHostAddr (DNS), getHostByAddr, getLocalHostName, isReachable (ICMP) |
| `Inet6AddressImpl` | 4 | lookupAllHostAddr (DNS), getHostByAddr, getLocalHostName, isReachable |
| `NetworkInterface` | 12 | getAll, getByName, getByIndex, getByInetAddress, boundInetAddress, getMTU, getMacAddr, isLoopback, isP2P, isUp, supportsMulticast, init |

**Key C files:**
- `unix/native/libnet/Inet4AddressImpl.c` — DNS resolution via getaddrinfo
- `unix/native/libnet/Inet6AddressImpl.c` — DNS resolution
- `unix/native/libnet/NetworkInterface.c` — ioctl-based NIC enumeration

#### 5.2.2 NIO Channels — Sockets (`sun.nio.ch.*`) — 74 functions

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `Net` | 37 | socket, bind, connect, listen, accept, shutdown, poll, pollConnect, getIntOption, setIntOption, localPort, remotePort, localInetAddress, remoteInetAddress, available, sendOOB, multicast join/drop/block |
| `SocketDispatcher` | 4 | read, readv, write, writev |
| `DatagramDispatcher` | 5 | read, readv, write, writev, dup |
| `DatagramChannelImpl` | 3 | send, receive, disconnect |
| `UnixDomainSockets` | 6 | socket, bind, connect, accept, localAddress, init |
| `InheritedChannel` | 11 | open, close, dup, dup2, initIDs, soType, isConnected, addressFamily, peerPort, inetPeerAddress, unixPeerAddress |
| `EPoll` | 6 | create, ctl, wait, eventSize, eventsOffset, dataOffset |
| `PollSelectorImpl` | 1 | poll |
| `UnixAsyncSocketChannelImpl` | 1 | checkConnect |

**Key C files:**
- `unix/native/libnio/ch/Net.c` — **the biggest network native file** (~1,300 LOC)
- `unix/native/libnio/ch/SocketDispatcher.c`
- `unix/native/libnio/ch/DatagramChannelImpl.c`
- `unix/native/libnio/ch/DatagramDispatcher.c`
- `unix/native/libnio/ch/UnixDomainSockets.c`
- `linux/native/libnio/ch/EPoll.c`

#### 5.2.3 Support (`sun.net.*`) — 5 functions

| Java Class | Functions |
|-----------|-----------|
| `PortConfig` | getLower0, getUpper0 |
| `ResolverConfigurationImpl` | fallbackDomain0 |
| `DefaultProxySelector` | init, getSystemProxies |

### 5.3 PROCESS EXECUTION (~19 functions) — **HIGH PRIORITY**

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `ProcessImpl` | 2 | **forkAndExec** (the critical one — forks and execs), init |
| `ProcessHandleImpl` | 7 | getCurrentPid, getProcessPids, destroy (kill), isAlive, parent, waitForProcessExit, initNative |
| `ProcessHandleImpl.Info` | 2 | info0 (reads /proc), initIDs |
| `ProcessEnvironment` | 1 | **environ** (reads all env vars) |
| `Runtime` | 5 | availableProcessors, freeMemory, totalMemory, maxMemory, gc |
| `Shutdown` | 2 | halt0, beforeHalt |

**Key C files:**
- `unix/native/libjava/ProcessImpl_md.c` — **THE process spawning implementation** (~700 LOC, uses fork/exec or posix_spawn)
- `unix/native/libjava/childproc.c` — child process setup helpers
- `unix/native/libjava/ProcessHandleImpl_unix.c` — process querying
- `unix/native/libjava/ProcessEnvironment_md.c` — reads `environ`
- `unix/native/jspawnhelper/jspawnhelper.c` — separate helper binary

### 5.4 ENVIRONMENT & SYSTEM PROPERTIES (~9 functions) — **HIGH PRIORITY**

| Java Class | Functions | Key Operations |
|-----------|-----------|----------------|
| `SystemProps.Raw` | 2 | **platformProperties** (reads OS info, user.home, user.name, java.io.tmpdir, etc.), **vmProperties** |
| `ProcessEnvironment` | 1 | environ (reads all env vars) |
| `System` | 6 | registerNatives, identityHashCode, mapLibraryName, setIn0, setOut0, setErr0 |
| `CgroupMetrics` | 4 | isContainerized, isUseContainerSupport, getTotalMemorySize, getTotalSwapSize |

**Key C files:**
- `unix/native/libjava/java_props_md.c` — **reads system properties** (getpwuid, uname, getenv, locale detection — ~700 LOC)
- `unix/native/libjava/ProcessEnvironment_md.c`
- `linux/native/libjava/CgroupMetrics.c`

### 5.5 FOREIGN FUNCTION & MEMORY API (~29 functions) — **ESCAPE HATCH**

| Java Class | Functions | Risk |
|-----------|-----------|------|
| `LibFallback` | 28 | FFI calls via libffi — allows calling arbitrary native functions |
| `ForeignLinkerSupport` | 1 | isSupported check |

**Key C files:**
- `share/native/libfallbackLinker/LibFallback.c` — wraps libffi
- `share/native/libsyslookup/syslookup.c` — exposes system symbols

### 5.6 NATIVE LIBRARY LOADING — **ESCAPE HATCH**

| Java Class | Functions | Risk |
|-----------|-----------|------|
| `NativeLibraries` | 3 | findBuiltinLib, **load** (dlopen), **unload** (dlclose) |
| `NativeLibrary` | 1 | findEntry0 (dlsym) |
| `RawNativeLibraries` | 2 | load0, unload0 |

These are in `share/native/libjava/NativeLibraries.c` and `RawNativeLibraries.c`.

---

## 6. Sandboxing Strategy Assessment

### Approach: Replace native functions with sandboxed versions

#### Tier 1 — Must intercept (blocks all external resource access)

| Category | Functions to Replace | Difficulty |
|----------|---------------------|------------|
| **File open/create** | `io_util_md.c:fileOpen`, `UnixNativeDispatcher:open0/openat0`, `UnixFileSystem:createFileExclusively0/createDirectory0` | MEDIUM — ~5 choke points |
| **Socket create/connect** | `Net:socket0/connect0/bind0/accept`, `UnixDomainSockets:socket0/connect0` | MEDIUM — ~4 choke points |
| **Process spawn** | `ProcessImpl:forkAndExec` | EASY — 1 choke point |
| **Env var access** | `ProcessEnvironment:environ`, `java_props_md.c` platform properties | EASY — 2 choke points |
| **Native library loading** | `NativeLibraries:load`, `RawNativeLibraries:load0` | EASY — 2 choke points |
| **FFI/Foreign** | `LibFallback:*`, `libsyslookup` | EASY — disable entirely |

#### Tier 2 — Should intercept (prevents information leakage)

| Category | Functions | Notes |
|----------|-----------|-------|
| DNS resolution | `Inet4AddressImpl:lookupAllHostAddr`, `Inet6AddressImpl:lookupAllHostAddr` | Can redirect to sandbox resolver |
| System properties | `SystemProps.Raw:platformProperties` | Return sanitized values |
| Network interface enumeration | `NetworkInterface:getAll/getByName` | Return virtual interfaces |
| Process listing | `ProcessHandleImpl:getProcessPids0` | Return empty/filtered |
| Cgroup info | `CgroupMetrics:*` | Return sanitized values |

#### Tier 3 — Nice to intercept (defense in depth)

| Category | Functions | Notes |
|----------|-----------|-------|
| File metadata | stat, lstat, fstat, access, chmod, chown, xattr | Already blocked if open is blocked |
| File watching | inotify_* | Already blocked if open is blocked |
| Signals | `Signal:handle0/raise0` | Mostly harmless |
| `halt0` / `Shutdown` | Can prevent JVM exit | Useful for long-running sandbox |

### Key architectural insight

The native code has **natural choke points** that make sandboxing feasible:

1. **File I/O**: Almost all file operations flow through `io_util_md.c` (for java.io) or
   `UnixNativeDispatcher.c` (for java.nio.file). The underlying POSIX calls (`open`, `openat`,
   `stat`, etc.) are the real enforcement points.

2. **Networking**: All socket operations flow through `Net.c` which wraps the POSIX socket API.
   DNS resolution goes through `getaddrinfo` in the Inet*AddressImpl files.

3. **Process spawning**: A single function `forkAndExec` in `ProcessImpl_md.c` handles all
   process creation.

4. **Two implementation approaches**:
   - **Replace at JNI level**: Recompile the native libraries with modified implementations.
     Requires rebuilding ~100 .c files but gives full control.
   - **Replace at syscall level**: Use `LD_PRELOAD` or seccomp-BPF to intercept POSIX calls.
     Simpler but coarser-grained and can't virtualize (e.g., provide a virtual filesystem).
   - **Hybrid**: Replace JNI natives for the ~10-15 critical choke-point files while using
     seccomp as a safety net for anything missed.

### Estimated scope of work

| Component | Files to Modify | Estimated Lines |
|-----------|----------------|-----------------|
| File I/O sandbox layer | 3-4 key .c files | ~500-800 new LOC |
| Network sandbox layer | 2-3 key .c files | ~300-500 new LOC |
| Process sandbox (block/virtualize) | 1 .c file | ~100-200 new LOC |
| Environment sandbox | 2 .c files | ~100-200 new LOC |
| FFI/native loading (disable) | 2 .c files | ~50 new LOC |
| **Total** | **~10-15 files** | **~1,000-1,700 new LOC** |

---

## 7. Complete Native Library Dependency Graph

```
libjava ──→ libjvm (JVM_* calls)
   │
   ├── System calls: open, read, write, close, stat, mkdir, rmdir,
   │   unlink, rename, fork, exec, getenv, getpwuid, uname, dlopen
   │
   └── Links: -ldl (Linux)

libnet ──→ libjava, libjvm
   │
   ├── System calls: socket, connect, bind, listen, accept, send, recv,
   │   getaddrinfo, gethostbyaddr, ioctl (SIOCGIFADDR etc.)
   │
   └── Links: -ldl (Linux)

libnio ──→ libjava, libnet
   │
   ├── System calls: open, openat, read, write, pread, pwrite, mmap,
   │   munmap, fstat, stat, lstat, mkdir, rmdir, unlink, link, symlink,
   │   readlink, rename, chmod, chown, epoll_create, epoll_ctl,
   │   epoll_wait, inotify_init, inotify_add_watch, sendfile,
   │   copy_file_range, socket, socketpair, fadvise
   │
   └── Links: -ldl -lpthread (Linux)

libzip ──→ libjava, libjvm
   │
   └── Links: -lz (or bundled zlib)

libjli ──→ (standalone, launcher only)
   │
   └── Links: -ldl -lpthread -lz (Linux)

libverify ──→ libjvm

libfallbackLinker ──→ libffi

libsyslookup ──→ -ldl -lm
```

---

## 8. Files Cross-Reference (Linux Target — Most Important for Sandboxing)

### Critical files to modify/replace:

| Priority | File | LOC | What it does |
|----------|------|-----|-------------|
| **P0** | `unix/native/libjava/io_util_md.c` | ~340 | Core POSIX file open/read/write |
| **P0** | `unix/native/libnio/fs/UnixNativeDispatcher.c` | ~1,500 | NIO filesystem operations |
| **P0** | `unix/native/libnio/ch/Net.c` | ~1,300 | Socket create/connect/bind/accept |
| **P0** | `unix/native/libjava/ProcessImpl_md.c` | ~700 | fork+exec process spawning |
| **P1** | `unix/native/libjava/UnixFileSystem_md.c` | ~600 | java.io.File metadata operations |
| **P1** | `unix/native/libnio/ch/UnixFileDispatcherImpl.c` | ~500 | NIO file channel I/O |
| **P1** | `unix/native/libnet/Inet4AddressImpl.c` | ~450 | DNS resolution |
| **P1** | `unix/native/libnet/Inet6AddressImpl.c` | ~350 | DNS resolution |
| **P1** | `unix/native/libjava/java_props_md.c` | ~700 | System property discovery |
| **P1** | `unix/native/libjava/ProcessEnvironment_md.c` | ~60 | Environment variable access |
| **P2** | `share/native/libjava/NativeLibraries.c` | ~200 | dlopen/dlclose |
| **P2** | `share/native/libfallbackLinker/LibFallback.c` | ~300 | FFI calls |
| **P2** | `unix/native/libnio/ch/SocketDispatcher.c` | ~150 | Socket read/write |
| **P2** | `unix/native/libnio/ch/DatagramChannelImpl.c` | ~250 | UDP send/receive |
| **P2** | `unix/native/libnio/ch/UnixDomainSockets.c` | ~250 | Unix domain sockets |
