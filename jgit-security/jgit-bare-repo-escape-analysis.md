# JGit Bare Repository Escape Analysis

## Context

A web application clones user repositories from GitHub as **bare** repos into adjacent filesystem directories, then uses JGit's RevWalk / TreeWalk / ObjectReader APIs to serve file content. The question is whether git symlinks — or other mechanisms — can be used by one user to read content from an adjacent user's bare repository.

---

## How JGit Reads Files from a Bare Repository

The typical application pattern is:

```java
try (Repository repo = new FileRepository("/repos/user-a/repo.git");
     RevWalk rw = new RevWalk(repo);
     ObjectReader reader = repo.newObjectReader()) {

    RevCommit commit = rw.parseCommit(repo.resolve("refs/heads/main"));
    RevTree tree = commit.getTree();

    TreeWalk tw = TreeWalk.forPath(repo, "path/to/file", tree);
    FileMode mode = tw.getFileMode(0);         // e.g. REGULAR_FILE, SYMLINK, TREE
    ObjectId blobId = tw.getObjectId(0);
    ObjectLoader loader = reader.open(blobId); // reads objects/xx/xxxxxxxx... by SHA-1
    byte[] bytes = loader.getBytes();
}
```

All object reads are addressed **exclusively by SHA-1 hash**. The file path on disk is always:

```
objects/<first-2-hex-chars>/<remaining-38-hex-chars>
```

There is no filesystem traversal based on repository content during ODB reads.

---

## Symlinks in Bare Repositories

### How Git Represents Symlinks

A symlink in a git tree is stored as:
- **Mode**: `0120000` (`FileMode.SYMLINK`, `TYPE_SYMLINK = 0120000`)
- **Object type**: blob (`OBJ_BLOB`) — the blob content is the symlink **target path** as raw bytes

For example, a symlink `link → ../../other-repo/secret.txt` is stored as a blob containing the string `../../other-repo/secret.txt`.

### JGit Behavior with Symlinks

**`FileMode.SYMLINK` (`FileMode.java:65`)**: The `SYMLINK` constant maps to object type `OBJ_BLOB`. JGit treats symlinks as blobs with a special mode bit.

**`ObjectWalk.java:411`, `ObjectWalk.java:795`**: During object graph traversal, `TYPE_SYMLINK` entries are handled identically to `TYPE_FILE` — they are treated as blob leaves. JGit enqueues the blob object ID for loading; it does **not** dereference or follow the path stored inside.

**`ObjectReader.open(blobId)`**: Opens the blob file at `objects/xx/xxxxxxxx...` by hash. The blob content (the symlink target path string) is returned as raw bytes. **JGit never interprets this string as a filesystem path and never accesses the target.**

**`TreeWalk.forPath(path, tree)`**: Navigates the tree structure by comparing path **component names** against the tree entries. Because `..` is a rejected character sequence for tree entry names (see ObjectChecker below), a TreeWalk cannot be made to navigate outside the repository tree by crafting tree entry names.

**`PathFilter.create(path)` (`PathFilter.java:48`)**: Strips trailing `/` characters, but performs **no further validation**. It does not reject `..` in the path argument. However, since git tree entries can never have `..` as a name (ObjectChecker rejects them), passing `../../foo` to `forPath` will simply fail to find a matching entry — it cannot reach outside the tree.

### `ObjectChecker` — What It Does and Doesn't Validate

`ObjectChecker.checkPathSegment2()` (`ObjectChecker.java:852`) reports (but does not hard-fail by default) the following for tree entry **names**:
- `HAS_DOT` — entry named `.`
- `HAS_DOTDOT` — entry named `..`
- `HAS_DOTGIT` — entry named `.git` (various case/encoding forms)
- `FULL_PATHNAME` — entry name containing `/`

Note that **`HAS_DOTDOT` and `HAS_DOTGIT` are configurable warnings**, not mandatory errors. If JGit's `receive.fsckObjects` is disabled (the default in many deployments), a pushed object with `..` as a tree entry name would be accepted. However, even if accepted into the ODB, the `..` entry name would be returned as-is by TreeWalk — it would **not** cause filesystem traversal in bare ODB reads.

**`ObjectChecker.checkBlob()` (`ObjectChecker.java:1266`)**: Does nothing — blobs are considered always valid. This means **the content of a symlink blob (the target path string) is never inspected or validated by JGit**. A symlink pointing to `../../../etc/passwd` or `../../other-user-repo/objects/info/packs` passes validation without any warning.

### Verdict on Symlinks at the JGit Layer

**JGit itself is safe for bare repo ODB reads.** Symlink blobs are returned as opaque bytes. No filesystem path following occurs inside JGit for these operations.

---

## Risk: Application-Level Symlink Following (HIGH)

The real risk is at the **application layer**, not in JGit.

A common but incorrect pattern is:

```java
FileMode mode = tw.getFileMode(0);
byte[] content = reader.open(tw.getObjectId(0)).getBytes();

// ❌ DANGEROUS: naive implementation that follows symlinks
if (mode == FileMode.SYMLINK) {
    String target = RawParseUtils.decode(content);
    // If target = "../../other-user/repo.git/objects/pack/pack-xxx.pack"
    // this opens a file from the adjacent repository
    return Files.readAllBytes(repoWorkDir.resolve(target));
}
```

Since the blob content (the symlink target path string) is arbitrary and completely attacker-controlled — and is **never validated by JGit** — a malicious user can push a symlink pointing to any relative or absolute path. An application that follows the symlink target on the filesystem to serve content would be vulnerable to:

- Reading files from adjacent bare repositories (e.g., pack files, HEAD, config)
- Reading server-side files outside the git directory entirely (e.g., `/etc/passwd`, private keys)

**Mitigation**: When serving file content, always check `tw.getFileMode(0)`. If `FileMode.SYMLINK`, either:
1. Return the blob bytes as-is (serve the raw symlink target string, not the linked content), or
2. Refuse to serve symlink entries, or
3. Validate that the resolved path stays within the repository root using `Path.normalize()` and a prefix check — but this only applies if you have a checked-out working tree, which you don't in a bare clone.

---

## Risk: `objects/info/alternates` Path Traversal (MEDIUM — Conditional)

### How It Works

`ObjectDirectory.loadAlternates()` (`ObjectDirectory.java:724`) reads lines from `<repo>/objects/info/alternates` at object-lookup time (lazy, first access). Each line is passed to `openAlternate(String location)` which calls:

```java
// ObjectDirectory.java:742
final File objdir = fs.resolve(objects, location);
```

`FS.resolve()` (`FS.java:1144`) is:
```java
public File resolve(File dir, String name) {
    File abspn = new File(name);
    if (abspn.isAbsolute())
        return abspn;           // absolute path returned directly
    return new File(dir, name); // relative path resolved against objects/
}
```

If `objects/info/alternates` contains:
```
../../other-user/repo.git/objects
```

JGit resolves this to the adjacent repository's object directory and opens it as an alternate ODB. Any SHA-1 not found in the current repo is then looked up in the adjacent repo. **This is a direct adjacent-repository object read.**

### Can an Attacker Write This File?

**Through standard `git push`**: No. `objects/info/alternates` is a git server-side metadata file. Git's object transfer protocol (smart HTTP, SSH, pack protocol v1/v2) only transfers pack objects and updates refs. This file is never included in what gets pushed.

**Through dumb HTTP clone**: `WalkFetchConnection` reads `info/alternates` from the remote HTTP server. However, `TransportHttp.openAlternate()` (`TransportHttp.java:1413`) returns a new `HttpObjectDB(new URL(httpObjectsUrl, location))` — a remote HTTP URL, not a local filesystem path. The local `objects/info/alternates` is never written during a clone.

**Application bugs**: If the application has any write primitive that allows user-controlled content into `<repo>/objects/info/alternates`, the attack is trivially successful. This includes scenarios such as:
- A "shared objects" feature where the app writes alternates to speed up similar repos
- A misconfigured `git clone --shared` or `--reference` invocation
- Any server-side hook that writes user-controlled data to this file

**Verdict**: Not exploitable through normal git push, but represents a high-severity latent risk if any application code touches this file with user-controlled input.

---

## Risk: Submodule URL Injection via `.gitmodules` (MEDIUM — Depends on App)

### What JGit Validates

`ReceivePack` calls `SubmoduleValidator.assertValidGitModulesFile()` (`ReceivePack.java:1583`) on pushed `.gitmodules` content — but **only if `receive.fsckObjects` is enabled**.

`assertValidSubmoduleUri()` (`SubmoduleValidator.java:110`) only rejects URIs that **start with `-`**:
```java
public static void assertValidSubmoduleUri(String uri) throws SubmoduleValidationException {
    if (uri.startsWith("-")) {  // only check: reject leading dash
        throw new SubmoduleValidationException(...);
    }
}
```

This means the following `.gitmodules` entries **pass validation**:
```ini
[submodule "escape"]
    url = file:///repos/other-user/repo.git
    path = sub

[submodule "escape2"]
    url = ../other-user/repo.git
    path = sub2
```

`assertValidSubmodulePath()` similarly only blocks paths starting with `-`.

`assertValidSubmoduleName()` rejects names containing `..` path segments — but names are only used for `$GIT_DIR/modules/<name>` storage; the `url` and `path` fields are unconstrained.

### Impact

If the application processes `.gitmodules` to clone or read submodule content, and it resolves `file://` or relative submodule URLs, an attacker can point a submodule at an adjacent user's repository. Whether this constitutes a real vulnerability depends entirely on what the app does with submodule metadata.

---

## Risk: `config` File Includes (LOW — Not Exploitable via Git Push)

`FileBasedConfig.readIncludedConfig()` (`FileBasedConfig.java:255`) processes `[include] path = ...` directives in the git config file. It resolves relative paths against the config file's parent directory:

```java
file = fs.resolve(configFile.getParentFile(), relPath);
```

For a bare repo at `/repos/user-a/repo.git`, the config is at `/repos/user-a/repo.git/config`. An include like:
```ini
[include]
    path = ../../user-b/repo.git/config
```
would read user B's config file.

However, the bare repo's `config` file is written by JGit's `CloneCommand` and reflects the remote URL and basic settings. **Users have no way to inject content into this file through standard git operations.** This attack requires direct filesystem write access.

---

## Summary Table

| Vector | JGit Layer Safe? | App-Level Risk | Exploitable via `git push`? |
|---|---|---|---|
| Symlink blob content | ✅ Safe (blob returned as raw bytes) | HIGH if app follows target path on filesystem | ✅ Yes — no validation of blob content |
| `objects/info/alternates` | ⚠️ No path sanitization in `FS.resolve()` | HIGH if file is writable | ❌ No — not pushed by git protocol |
| Submodule URL in `.gitmodules` | ⚠️ `file://` URLs not blocked | MEDIUM if app follows submodule URLs | ✅ Yes — `assertValidSubmoduleUri` only blocks `-` prefix |
| `PathFilter` path traversal | ✅ Safe (tree entries can't have `..`) | Low | N/A |
| `config` include injection | ⚠️ No path sanitization | Low | ❌ No — config not pushed |

---

## Recommendations

1. **Always check `FileMode` before serving content.** Treat `FileMode.SYMLINK` entries as opaque data (return the blob bytes as the "file content") rather than following them as filesystem paths. Never call `Files.readAllBytes(workDir.resolve(symlinkTarget))` on attacker-controlled symlink target strings.

2. **Protect `objects/info/alternates`.** Ensure no application code path writes user-controlled content to this file. Audit any use of `git clone --shared`, `--reference`, or alternates setup.

3. **Enable `receive.fsckObjects`** in your JGit-based receive-pack configuration. This enables `ObjectChecker` to detect malformed tree entries (`.git`, `..`) before they land in the ODB. Set `transfer.fsckObjects = true` in the bare repo's config.

4. **Validate submodule URLs** if your application follows submodule references. Block `file://` schemes and bare relative paths (`../`) before resolving them.

5. **`objects/info/alternates` file permissions.** Consider making this file read-only or owned by the server process to prevent accidental writes.

---

## JGit Source References

| File | Key Finding |
|---|---|
| `lib/FileMode.java:65` | `SYMLINK` maps to `OBJ_BLOB` — symlinks are blobs |
| `revwalk/ObjectWalk.java:411` | Symlink entries treated as blob leaves, not followed |
| `lib/ObjectChecker.java:1266` | `checkBlob()` is a no-op — symlink target content never validated |
| `lib/ObjectChecker.java:852` | `HAS_DOTDOT` is a configurable warning, not a hard error |
| `internal/storage/file/ObjectDirectory.java:724` | `loadAlternates()` reads `objects/info/alternates` without path sanitization |
| `util/FS.java:1144` | `FS.resolve()` accepts absolute paths and relative `../` paths |
| `storage/file/FileBasedConfig.java:255` | `readIncludedConfig()` resolves include paths relative to config file |
| `internal/submodule/SubmoduleValidator.java:110` | `assertValidSubmoduleUri()` only blocks `-`-prefixed URLs; `file://` is allowed |
| `treewalk/filter/PathFilter.java:48` | No `..` validation on the caller-supplied path argument |
| `dircache/Checkout.java:174` | Checkout DOES follow symlinks (non-bare only) — `fs.createSymLink(f, target)` |
