# JGit `java.io` and `java.nio` Package Usage Report

**Repository:** https://github.com/eclipse-jgit/jgit
**Commit analyzed:** `2501792` (PackIndexMerger: replace constructor with Builder)
**Date:** 2026-02-18
**Total Java files in codebase:** 1,882

---

## Executive Summary

| Package | Distinct Classes | Files Using It | Coverage |
|---------|----------------:|---------------:|---------:|
| `java.io` | 41 | 1,047 | 55.6% |
| `java.nio` | 47 | 235 | 12.5% |

- `java.io.IOException` is used in **926 files** — nearly half the entire codebase.
- `java.io.File` (326 files) is the legacy file abstraction; `java.nio.file.Path`/`Files` (91/113 files) show active migration in progress but are far behind.
- No wildcard imports (`java.io.*` or `java.nio.*`) exist anywhere; every class is imported explicitly.

---

## Part 1 — `java.io` Package

### 1.1 Class Usage Frequency

Number of files importing each `java.io` class, sorted by prevalence:

| Rank | Class | Files |
|------|-------|------:|
| 1 | `java.io.IOException` | 926 |
| 2 | `java.io.File` | 326 |
| 3 | `java.io.InputStream` | 181 |
| 4 | `java.io.OutputStream` | 161 |
| 5 | `java.io.ByteArrayOutputStream` | 94 |
| 6 | `java.io.ByteArrayInputStream` | 65 |
| 7 | `java.io.FileNotFoundException` | 64 |
| 8 | `java.io.FileInputStream` | 52 |
| 9 | `java.io.FileOutputStream` | 51 |
| 10 | `java.io.BufferedReader` | 43 |
| 11 | `java.io.InputStreamReader` | 40 |
| 12 | `java.io.EOFException` | 31 |
| 13 | `java.io.BufferedInputStream` | 30 |
| 14 | `java.io.BufferedOutputStream` | 25 |
| 15 | `java.io.OutputStreamWriter` | 24 |
| 16 | `java.io.Writer` | 19 |
| 17 | `java.io.UnsupportedEncodingException` | 18 |
| 18 | `java.io.PrintWriter` | 18 |
| 19 | `java.io.UncheckedIOException` | 16 |
| 20 | `java.io.PrintStream` | 16 |
| 21 | `java.io.InterruptedIOException` | 14 |
| 22 | `java.io.Serializable` | 13 |
| 23 | `java.io.Reader` | 9 |
| 24 | `java.io.Closeable` | 9 |
| 25 | `java.io.BufferedWriter` | 9 |
| 26 | `java.io.StringWriter` | 8 |
| 27 | `java.io.StreamCorruptedException` | 8 |
| 28 | `java.io.RandomAccessFile` | 7 |
| 29 | `java.io.PipedOutputStream` | 4 |
| 30 | `java.io.PipedInputStream` | 4 |
| 31 | `java.io.FilterInputStream` | 4 |
| 32 | `java.io.DataInput` | 4 |
| 33 | `java.io.DataOutput` | 3 |
| 34 | `java.io.StringReader` | 2 |
| 35 | `java.io.ObjectOutputStream` | 2 |
| 36 | `java.io.ObjectInputStream` | 2 |
| 37 | `java.io.FilterOutputStream` | 2 |
| 38 | `java.io.Console` | 2 |
| 39 | `java.io.InvalidObjectException` | 1 |
| 40 | `java.io.FilenameFilter` | 1 |
| 41 | `java.io.FileDescriptor` | 1 |

### 1.2 Category Breakdown

| Category | Classes | Total file-uses |
|----------|---------|---------------:|
| Exception types | `IOException`, `FileNotFoundException`, `EOFException`, `UnsupportedEncodingException`, `UncheckedIOException`, `InterruptedIOException`, `StreamCorruptedException`, `InvalidObjectException` | 1,137 |
| Core stream abstractions | `InputStream`, `OutputStream`, `Reader`, `Writer`, `Closeable` | 379 |
| File-backed I/O | `File`, `FileInputStream`, `FileOutputStream`, `RandomAccessFile`, `FileDescriptor`, `FilenameFilter` | 387 |
| Buffered/wrapped streams | `BufferedInputStream`, `BufferedOutputStream`, `BufferedReader`, `BufferedWriter`, `InputStreamReader`, `OutputStreamWriter` | 161 |
| In-memory streams | `ByteArrayOutputStream`, `ByteArrayInputStream`, `StringWriter`, `StringReader` | 169 |
| Print/text output | `PrintWriter`, `PrintStream` | 34 |
| Piped streams | `PipedInputStream`, `PipedOutputStream` | 8 |
| Low-level data I/O | `DataInput`, `DataOutput` | 7 |
| Object serialization | `ObjectInputStream`, `ObjectOutputStream`, `Serializable` | 17 |
| Filter streams | `FilterInputStream`, `FilterOutputStream` | 6 |
| Terminal | `Console` | 2 |

### 1.3 Per-Module Coverage

| Module | `java.io` Files | Total Java Files | Coverage |
|--------|---------------:|----------------:|---------:|
| `org.eclipse.jgit` (core) | 517 | 960 | 53.9% |
| `org.eclipse.jgit.test` | 280 | 499 | 56.1% |
| `org.eclipse.jgit.pgm` | 62 | 87 | 71.3% |
| `org.eclipse.jgit.ssh.apache` | 34 | 69 | 49.3% |
| `org.eclipse.jgit.http.server` | 25 | 35 | 71.4% |
| `org.eclipse.jgit.lfs` | 18 | 33 | 54.5% |
| `org.eclipse.jgit.pgm.test` | 17 | 36 | 47.2% |
| `org.eclipse.jgit.http.test` | 14 | 26 | 53.8% |
| `org.eclipse.jgit.ssh.apache.test` | 10 | 16 | 62.5% |
| `org.eclipse.jgit.lfs.server` | 10 | 14 | 71.4% |
| `org.eclipse.jgit.junit` | 7 | 14 | 50.0% |
| `org.eclipse.jgit.lfs.test` | 6 | 9 | 66.7% |
| `org.eclipse.jgit.archive` | 6 | 9 | 66.7% |
| `org.eclipse.jgit.benchmarks` | 5 | 8 | 62.5% |
| `org.eclipse.jgit.ssh.apache.agent` | 5 | 9 | 55.6% |
| `org.eclipse.jgit.ant` | 4 | 4 | 100.0% |
| `org.eclipse.jgit.junit.ssh` | 4 | 4 | 100.0% |
| `org.eclipse.jgit.ssh.jsch.test` | 4 | 5 | 80.0% |
| `org.eclipse.jgit.gpg.bc` | 4 | 12 | 33.3% |
| `org.eclipse.jgit.http.apache` | 3 | 4 | 75.0% |
| `org.eclipse.jgit.ssh.jsch` | 3 | 6 | 50.0% |
| `org.eclipse.jgit.lfs.server.test` | 3 | 5 | 60.0% |
| `org.eclipse.jgit.gpg.bc.test` | 2 | 4 | 50.0% |
| `org.eclipse.jgit.junit.http` | 2 | 7 | 28.6% |
| `org.eclipse.jgit.ant.test` | 1 | 1 | 100.0% |
| `org.eclipse.jgit.ui` | 1 | 6 | 16.7% |
| `org.eclipse.jgit.coverage` | 0 | 0 | — |
| `org.eclipse.jgit.packaging` | 0 | 0 | — |
| **Total** | **1,047** | **1,882** | **55.6%** |

### 1.4 Files with Most `java.io` Imports

| `java.io` Imports | File |
|:-----------------:|------|
| 10 | `org.eclipse.jgit/src/org/eclipse/jgit/util/FS.java` |
| 10 | `org.eclipse.jgit/src/org/eclipse/jgit/transport/TransportHttp.java` |
| 10 | `org.eclipse.jgit.test/tst/org/eclipse/jgit/transport/WalkEncryptionTest.java` |
| 10 | `org.eclipse.jgit.test/tst/org/eclipse/jgit/indexdiff/IndexDiffWithSymlinkTest.java` |
| 9 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/PackInserter.java` |
| 9 | `org.eclipse.jgit.pgm.test/tst/org/eclipse/jgit/pgm/ArchiveTest.java` |
| 9 | `org.eclipse.jgit.lfs/src/org/eclipse/jgit/lfs/LfsPointer.java` |
| 8 | `org.eclipse.jgit/src/org/eclipse/jgit/util/TemporaryBuffer.java` |
| 8 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/transport/http/NetscapeCookieFile.java` |
| 8 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/RefDirectory.java` |
| 8 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/FileReftableStack.java` |
| 8 | `org.eclipse.jgit/src/org/eclipse/jgit/dircache/DirCache.java` |
| 8 | `org.eclipse.jgit.pgm/src/org/eclipse/jgit/pgm/TextBuiltin.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/transport/WalkRemoteObjectDatabase.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/transport/UploadPack.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/transport/AmazonS3.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/lib/Repository.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/UnpackedObject.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/Pack.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/ObjectDirectoryInserter.java` |

### 1.5 Deep Dive: `RandomAccessFile` (7 files)

`RandomAccessFile` is used for low-level byte-offset access to binary files — a pattern that `java.nio.channels.FileChannel` can also serve, but `RandomAccessFile` remains here for historical reasons or where seek+read convenience outweighs the NIO migration cost.

| File | Mode | Purpose |
|------|:----:|---------|
| `internal/storage/file/Pack.java` | `"r"` (long-lived field) | Random-seek reads of object data from a `.pack` file, held for the pack's lifetime, serialized by a `readLock` |
| `internal/storage/file/ObjectDirectoryPackParser.java` | `"rw"` (field, closed after parse) | Writes incoming pack bytes to a temp file; seeks back to write the final SHA-1 checksum, then `fsync`s and renames to permanent location |
| `internal/storage/file/PackInserter.java` (inner `PackStream`) | `"rw"` (field) | Builds a new pack file; calls `file.getFD()` to construct a `FileOutputStream` that shares the same OS file descriptor — enabling both sequential writes and seek-back reads without reopening the file. A code comment explicitly warns never to close the `RandomAccessFile` from within a wrapping stream. |
| `internal/storage/file/GC.java` (inner `PidLock`) | `"rw"` (field) | Holds a `FileChannel` + `FileLock` on `gc.pid` to prevent concurrent GC runs; writes the current process's PID/host info into the lock file so stale locks can be detected |
| `internal/storage/file/PackFileSnapshot.java` | `"r"` (try-with-resources) | Short-lived open: seeks to last 20 bytes of a `.pack` file to read the trailing SHA-1 checksum, used for change detection without re-reading the file |
| `http.server/FileSender.java` | `"r"` (long-lived field) | Serves dumb-HTTP Git clients; uses `seek()` to honor `Range:` HTTP headers and stream exactly the requested byte range of pack/info files |
| `org.eclipse.jgit.test/HugeFileTest.java` | `"rw"` (try-with-resources) | Test-only (`@Ignore`d): creates sparse files >4 GiB via `setLength()` and mutates single bytes via `write()` to exercise large-file and index-overflow handling |

### 1.6 Deep Dive: `FileDescriptor` (1 file)

`FileDescriptor` is used in exactly one file: `org.eclipse.jgit.pgm/src/org/eclipse/jgit/pgm/TextBuiltin.java`.

`TextBuiltin` is the abstract base class for all JGit CLI commands. Its `init()` method wires up the three standard I/O streams. The static constants `FileDescriptor.in`, `FileDescriptor.out`, and `FileDescriptor.err` are used as **fallbacks** when streams have not been pre-configured by a caller:

```java
if (ins == null)
    ins = new FileInputStream(FileDescriptor.in);    // stdin
if (outs == null)
    outs = new FileOutputStream(FileDescriptor.out); // stdout
if (errs == null)
    errs = new FileOutputStream(FileDescriptor.err); // stderr
```

The `if (x == null)` guards mean that when `initRaw()` has already been called by a test harness or embedding application (injecting piped streams), the real `FileDescriptor.*` values are never opened. This allows CLI commands to be driven programmatically with captured I/O.

---

## Part 2 — `java.nio` Package

### 2.1 Class Usage Frequency

47 distinct `java.nio` classes are used across 235 files (12.5% of the codebase):

| Rank | Class | Files |
|------|-------|------:|
| 1 | `java.nio.file.Files` | 113 |
| 2 | `java.nio.file.Path` | 91 |
| 3 | `java.nio.charset.StandardCharsets` | 44 |
| 4 | `java.nio.ByteBuffer` | 44 |
| 5 | `java.nio.file.Paths` | 21 |
| 6 | `java.nio.charset.Charset` | 21 |
| 7 | `java.nio.file.StandardCopyOption` | 18 |
| 8 | `java.nio.file.InvalidPathException` | 15 |
| 9 | `java.nio.file.NoSuchFileException` | 13 |
| 10 | `java.nio.channels.Channels` | 11 |
| 11 | `java.nio.file.attribute.FileTime` | 10 |
| 12 | `java.nio.file.StandardOpenOption` | 9 |
| 13 | `java.nio.file.LinkOption` | 8 |
| 14 | `java.nio.channels.FileChannel` | 8 |
| 15 | `java.nio.file.attribute.BasicFileAttributes` | 7 |
| 16 | `java.nio.charset.UnsupportedCharsetException` | 7 |
| 17 | `java.nio.charset.IllegalCharsetNameException` | 6 |
| 18 | `java.nio.channels.ReadableByteChannel` | 6 |
| 19 | `java.nio.charset.CharacterCodingException` | 5 |
| 20 | `java.nio.CharBuffer` | 5 |
| 21 | `java.nio.file.DirectoryStream` | 4 |
| 22 | `java.nio.file.attribute.PosixFilePermission` | 3 |
| 23 | `java.nio.file.FileStore` | 3 |
| 24 | `java.nio.file.DirectoryNotEmptyException` | 3 |
| 25 | `java.nio.charset.CharsetEncoder` | 3 |
| 26 | `java.nio.file.attribute.PosixFileAttributeView` | 2 |
| 27 | `java.nio.file.attribute.BasicFileAttributeView` | 2 |
| 28 | `java.nio.file.SimpleFileVisitor` | 2 |
| 29 | `java.nio.file.FileVisitResult` | 2 |
| 30 | `java.nio.file.FileSystemException` | 2 |
| 31 | `java.nio.file.AtomicMoveNotSupportedException` | 2 |
| 32 | `java.nio.file.AccessDeniedException` | 2 |
| 33 | `java.nio.charset.CodingErrorAction` | 2 |
| 34 | `java.nio.channels.WritableByteChannel` | 2 |
| 35 | `java.nio.file.attribute.PosixFileAttributes` | 1 |
| 36 | `java.nio.file.FileVisitOption` | 1 |
| 37 | `java.nio.file.FileAlreadyExistsException` | 1 |
| 38 | `java.nio.file.DirectoryIteratorException` | 1 |
| 39 | `java.nio.file.CopyOption` | 1 |
| 40 | `java.nio.charset.CoderResult` | 1 |
| 41 | `java.nio.charset.CharsetDecoder` | 1 |
| 42 | `java.nio.channels.OverlappingFileLockException` | 1 |
| 43 | `java.nio.channels.FileLock` | 1 |
| 44 | `java.nio.channels.FileChannel.MapMode` | 1 |
| 45 | `java.nio.channels.ClosedByInterruptException` | 1 |
| 46 | `java.nio.MappedByteBuffer` | 1 |
| 47 | `java.nio.InvalidMarkException` | 1 |

### 2.2 Sub-Package Breakdown

| Sub-package | Import lines | Primary role |
|-------------|------------:|--------------|
| `java.nio.file` | 312 | NIO.2 filesystem API — `Files`, `Path`, copy/move options, exception types |
| `java.nio.charset` | 90 | Character encoding — `StandardCharsets`, `Charset`, codec error handling |
| `java.nio` (buffers) | 51 | Direct/heap buffers — `ByteBuffer`, `CharBuffer`, `MappedByteBuffer` |
| `java.nio.channels` | 31 | Channel I/O — `FileChannel`, `ReadableByteChannel`, `FileLock` |
| `java.nio.file.attribute` | 25 | File metadata — `FileTime`, `PosixFilePermission`, `BasicFileAttributes` |

### 2.3 Per-Module Coverage

| Module | `java.nio` Files | Total Java Files | Coverage |
|--------|----------------:|----------------:|---------:|
| `org.eclipse.jgit` (core) | 83 | 960 | 8.6% |
| `org.eclipse.jgit.test` | 73 | 499 | 14.6% |
| `org.eclipse.jgit.ssh.apache` | 18 | 69 | 26.1% |
| `org.eclipse.jgit.ssh.apache.test` | 8 | 16 | 50.0% |
| `org.eclipse.jgit.lfs` | 9 | 33 | 27.3% |
| `org.eclipse.jgit.benchmarks` | 5 | 8 | 62.5% |
| `org.eclipse.jgit.lfs.server.test` | 5 | 5 | 100.0% |
| `org.eclipse.jgit.pgm.test` | 5 | 36 | 13.9% |
| `org.eclipse.jgit.gpg.bc` | 4 | 12 | 33.3% |
| `org.eclipse.jgit.junit` | 4 | 14 | 28.6% |
| `org.eclipse.jgit.pgm` | 4 | 87 | 4.6% |
| `org.eclipse.jgit.lfs.test` | 3 | 9 | 33.3% |
| `org.eclipse.jgit.junit.ssh` | 3 | 4 | 75.0% |
| `org.eclipse.jgit.ssh.apache.agent` | 3 | 9 | 33.3% |
| `org.eclipse.jgit.lfs.server` | 3 | 14 | 21.4% |
| `org.eclipse.jgit.ssh.jsch.test` | 3 | 5 | 60.0% |
| `org.eclipse.jgit.http.test` | 1 | 26 | 3.8% |
| `org.eclipse.jgit.junit.http` | 1 | 7 | 14.3% |
| `org.eclipse.jgit.ant` | 0 | 4 | 0% |
| `org.eclipse.jgit.ant.test` | 0 | 1 | 0% |
| `org.eclipse.jgit.archive` | 0 | 9 | 0% |
| `org.eclipse.jgit.gpg.bc.test` | 0 | 4 | 0% |
| `org.eclipse.jgit.http.apache` | 0 | 4 | 0% |
| `org.eclipse.jgit.http.server` | 0 | 35 | 0% |
| `org.eclipse.jgit.ssh.jsch` | 0 | 6 | 0% |
| `org.eclipse.jgit.ui` | 0 | 6 | 0% |
| **Total** | **235** | **1,882** | **12.5%** |

### 2.4 Files with Most `java.nio` Imports

| `java.nio` Imports | File |
|:-----------------:|------|
| 17 | `org.eclipse.jgit/src/org/eclipse/jgit/util/FileUtils.java` |
| 11 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/GC.java` |
| 8 | `org.eclipse.jgit/src/org/eclipse/jgit/util/FS_POSIX.java` |
| 8 | `org.eclipse.jgit.lfs.server.test/tst/.../fs/LfsServerTest.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/util/RawParseUtils.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/util/FS_Win32.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/util/FS.java` |
| 7 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/LockFile.java` |
| 6 | `org.eclipse.jgit/src/org/eclipse/jgit/util/SystemReader.java` |
| 6 | `org.eclipse.jgit/src/org/eclipse/jgit/treewalk/WorkingTreeIterator.java` |
| 6 | `org.eclipse.jgit.test/tst/org/eclipse/jgit/util/FSTest.java` |
| 6 | `org.eclipse.jgit.gpg.bc/.../BouncyCastleGpgKeyLocator.java` |
| 5 | `org.eclipse.jgit/src/org/eclipse/jgit/transport/RefAdvertiser.java` |
| 5 | `org.eclipse.jgit/src/org/eclipse/jgit/patch/PatchApplier.java` |
| 5 | `org.eclipse.jgit/src/org/eclipse/jgit/lib/FileModeCache.java` |
| 5 | `org.eclipse.jgit/src/org/eclipse/jgit/internal/storage/file/RefDirectory.java` |
| 5 | `org.eclipse.jgit.test/tst/.../file/PackInserterTest.java` |
| 5 | `org.eclipse.jgit.test/tst/.../file/PackFileSnapshotTest.java` |
| 5 | `org.eclipse.jgit.test/tst/.../file/FileSnapshotTest.java` |
| 5 | `org.eclipse.jgit.ssh.apache/.../OpenSshServerKeyDatabase.java` |

---

## Part 3 — Cross-Package Analysis

### 3.1 `java.io` vs `java.nio` — File API Comparison

The coexistence of `java.io.File` (326 files) and `java.nio.file.Path`/`Files` (91/113 files) shows a **partially migrated codebase**:

| API | Files | Notes |
|-----|------:|-------|
| `java.io.File` (legacy) | 326 | Pervasive; used for paths, temp files, existence checks, and as `FileInputStream`/`FileOutputStream` arguments |
| `java.nio.file.Path` (modern) | 91 | Present in newer code and the `util/` layer; often coexists with `File` via `.toPath()` / `.toFile()` bridges |
| `java.nio.file.Files` (modern) | 113 | Used for copy, move, delete, attribute reads, and directory streaming |

`FileUtils.java` (17 NIO imports) is the nexus of this migration: it implements atomic file operations (`AtomicMoveNotSupportedException`, `StandardCopyOption.ATOMIC_MOVE`), POSIX permission management, and recursive directory deletion — all using NIO.2.

### 3.2 Stream APIs Compared

| API | Abstractions | Total file-uses |
|-----|-------------|---------------:|
| `java.io` streams | `InputStream`, `OutputStream`, `Reader`, `Writer`, + buffered wrappers | 540 |
| `java.nio` channels | `ReadableByteChannel`, `WritableByteChannel`, `FileChannel`, `Channels` | 25 |

Stream APIs still dominate overwhelmingly. NIO channels appear mainly for `FileChannel` locking (`GC.PidLock`), memory-mapped I/O (`MappedByteBuffer`), and bridging via `Channels.newInputStream()`.

### 3.3 Notable: Modules with Zero `java.nio` Usage

Several modules use `java.io` but no `java.nio` at all:

| Module | `java.io` files | `java.nio` files |
|--------|---------------:|----------------:|
| `org.eclipse.jgit.http.server` | 25 | 0 |
| `org.eclipse.jgit.archive` | 6 | 0 |
| `org.eclipse.jgit.ant` | 4 | 0 |
| `org.eclipse.jgit.ssh.jsch` | 3 | 0 |

These modules have not adopted NIO.2 at all and represent the oldest or most IO-stream-oriented parts of the codebase.

---

## Part 4 — Key Observations

### `IOException` is everywhere
926 files (49.2% of the entire codebase) declare `throws IOException` or catch it. This is unavoidable for a Git implementation — every object read, pack access, ref update, and network transfer can fail with an I/O error.

### `java.io.File` migration is incomplete
`java.io.File` (326 files) vs `java.nio.file.Path` (91 files) — the NIO.2 `Path` API is 3.5× less common than `File`. Newer utility code (especially `FileUtils.java`, `FS.java`, `LockFile.java`) has been migrated; older storage and transport code has not. This is the single largest modernization opportunity.

### Charset handling is explicit and correct
`StandardCharsets` (44 files) and `Charset` (21 files) are used where character encoding matters. The presence of `UnsupportedCharsetException` (7) and `IllegalCharsetNameException` (6) import counts shows that charset errors are handled rather than silently ignored.

### `ByteBuffer` is used for binary protocol parsing
`java.nio.ByteBuffer` (44 files) is the workhorse for parsing Git's binary wire and pack formats, especially in `RawParseUtils.java` and the pack-file layer. `CharBuffer` (5 files) is used for encoding/decoding text in the same layer.

### No wildcard imports anywhere
Neither `java.io.*` nor `java.nio.*` wildcard imports appear. All 88 classes (41 `java.io` + 47 `java.nio`) are imported explicitly.

### Low serialization footprint
Only 13 files use `Serializable`, 2 use `ObjectInputStream`/`ObjectOutputStream`. JGit persists data using Git's own binary formats, not Java object serialization.

### `RandomAccessFile` serves three distinct roles
Despite appearing in only 7 files, `RandomAccessFile` is used for three fundamentally different purposes: **random-access reading** (serving HTTP range requests, reading pack data), **read/write pack building** (sharing an fd with a `FileOutputStream` via `getFD()`), and **OS-level file locking** (bridging to `FileChannel.tryLock()` in `GC.PidLock`). It is not a candidate for simple removal.
