# JGit — File Existence Probing via `fetch/want-ref` Endpoint in JGit Protocol V2

**CVE status:** not yet assigned
**Affected component:** `org.eclipse.jgit` — `ProtocolV2Parser`, `RefDirectory.fileFor()`
**Affected versions:** JGit ≤ 7.5.0.202512021534-r (latest stable as of 2026-02-18)
**Protocol:** Git Smart HTTP, Protocol V2, `fetch` command with `want-ref`
**Config required:** `[uploadpack] allowRefInWant = true` in the served repo's config
**Authentication required:** No (if the server allows unauthenticated access)

---

## Impact

When a JGit HTTP server is configured with `uploadpack.allowRefInWant = true`, any client
can use the `want-ref` field as a **file existence oracle** for any path on the server
filesystem accessible to the JGit process, and can **exfiltrate the commit SHA and git
objects** for any file that contains a 40-character hex string (e.g. `FETCH_HEAD`, `HEAD`,
or ref files in neighboring git repositories).

**Scenario:** A git hosting server serves `/tmp/public` over HTTP. The same server has
`/tmp/secret` on the same disk (not served). `public.git`'s `FETCH_HEAD` contains the
commit SHA from a prior server-side operation against `secret.git`. An attacker reads
`FETCH_HEAD` via the traversal, obtains the secret commit SHA, and retrieves the git
object.

**Oracle behaviour:**

| Response | Meaning |
|---|---|
| HTTP 200 + `ERR invalid ref name …` | File does not exist at the traversed path |
| **HTTP 500** (empty body) | File **exists** and was read by the JVM; first ~4 KB in server log |
| HTTP 200 + `wanted-refs` section + packfile | File contained a valid SHA; **commit exfiltrated** |

**Prerequisite:** `allowRefInWant = true` is a non-default setting. It is documented as
enabling "object-id-less fetches" and is used by some CI/CD integrations. Any deployment
with this flag is affected.

---

## Quick Start

```
# 1. One-time setup: download jars, create public + secret repos, enable flag
bash start_server.sh setup

# 2. Start the server (stays in foreground)
bash start_server.sh serve

# 3. In a second terminal, run the exploit
python3 exploit.py
```

`start_server.sh setup` creates:

```
/tmp/jgit-demo/
  public.git/        ← served on port 7070; has allowRefInWant = true;
                        FETCH_HEAD contains the secret commit SHA
  secret.git/        ← NOT served; classified-feature branch
```

The exploit:
1. Probes `/etc/passwd` — gets HTTP 500 (file exists, content in server log).
2. Probes a nonexistent path — gets HTTP 200 (absent).
3. Reads `$GIT_DIR/FETCH_HEAD` — gets HTTP 200 + packfile containing the secret commit.

---

## How It Works

### Vulnerable code path

**1. `ProtocolV2Parser.parseFetchRequest()` — stores the raw want-ref string**

```java
// src/org/eclipse/jgit/transport/ProtocolV2Parser.java
} else if (line2.startsWith(PACKET_WANT_REF)) {
    reqBuilder.addWantedRef(line2.substring(PACKET_WANT_REF.length()));
    //                      ↑ raw client string, no isValidRefName() call
```

**2. `UploadPack` resolves the ref via `RefDatabase.exactRef()`**

```java
// UploadPack calls db.exactRef(wantedRef)
// → RefDirectory.exactRef("refs/heads/../../FETCH_HEAD")
// → RefDirectory.fileFor("refs/heads/../../FETCH_HEAD")
```

**3. `RefDirectory.fileFor()` — builds a `File` with no traversal guard**

```java
// src/org/eclipse/jgit/internal/storage/file/RefDirectory.java
File fileFor(String name) {
    if (name.startsWith(R_REFS)) {
        name = name.substring(R_REFS.length());   // strips "refs/"
        return new File(refsDir, name);            // NO traversal check
        //              ↑ refsDir = $GIT_DIR/refs/
        //  name = "heads/../../FETCH_HEAD"
        //  new File($GIT_DIR/refs, "heads/../../FETCH_HEAD")
        //  path string: $GIT_DIR/refs/heads/../../FETCH_HEAD
        //  OS resolves at open(): $GIT_DIR/FETCH_HEAD   ✓
    }
```

**4. The file is read and its content interpreted as a ref**

- If the file does not exist: `exactRef()` returns `null` → `UploadPack` sends
  `ERR invalid ref name` → HTTP 200.
- If the file exists but its content is not a valid SHA: `LockFile` or ref parsing throws
  `IOException("Not a ref: <name>: <content>")` → unhandled → **HTTP 500**; the
  exception message (containing the file content) appears in the server log.
- If the file exists and starts with a 40-char hex SHA: `exactRef()` returns a `Ref`
  pointing to that object. `UploadPack` includes it in `wanted-refs` and serves the
  object in a packfile → **HTTP 200 + secret commit exfiltrated**.

### File path arithmetic

```
want-ref "refs/heads/../../FETCH_HEAD"
  fileFor strips "refs/":  "heads/../../FETCH_HEAD"
  new File($GIT_DIR/refs/, "heads/../../FETCH_HEAD")
  path string:              $GIT_DIR/refs/heads/../../FETCH_HEAD
  OS resolves:              $GIT_DIR/FETCH_HEAD                  ✓

want-ref "refs/heads/" + "../../"*N + "etc/passwd"
  → after enough ".." to clear the filesystem root → /etc/passwd ✓
```

One `../` from `$GIT_DIR/refs/heads/` reaches `$GIT_DIR/refs/`.
Two `../` reach `$GIT_DIR/`.
Three or more keep traversing up the directory tree.

### Why the existing `receive-pack` guard does not protect here

`ReceivePack.parseCommand()` calls `Repository.isValidRefName()` before accepting any
ref name.  `ProtocolV2Parser` (the upload-pack Protocol V2 parser) has no equivalent
guard — the `want-ref` value is stored directly.

---

## Missing Security Control

`Repository.isValidRefName()` rejects any name containing `..` (among other patterns).
It is already called on every incoming ref in `ReceivePack` but **not** in
`ProtocolV2Parser.parseFetchRequest()`.

### Suggested one-line fix in `ProtocolV2Parser.parseFetchRequest()`

```java
} else if (line2.startsWith(PACKET_WANT_REF)) {
    String refName = line2.substring(PACKET_WANT_REF.length());
    if (!Repository.isValidRefName(refName)) {
        throw new PackProtocolException(
            MessageFormat.format(JGitText.get().invalidRefName, refName));
    }
    reqBuilder.addWantedRef(refName);
```

`Repository.isValidRefName("refs/heads/../../FETCH_HEAD")` returns `false` because the
`..` component is caught by the character-level loop:
```java
case '.':
    switch (p) {
    case '.': return false;   // two consecutive dots → invalid
```

---

## Comparison: What a Normal `want-ref` Does

A normal client sends `want-ref refs/heads/main`, which resolves to `$GIT_DIR/refs/heads/main`.
The file is read, its SHA returned in `wanted-refs`, and the commit packed into the response.
With path traversal the same mechanism operates on any file the JVM can open.

| `want-ref` value | File resolved | Result |
|---|---|---|
| `refs/heads/main` (normal) | `$GIT_DIR/refs/heads/main` | own branch SHA served |
| `refs/heads/../../FETCH_HEAD` | `$GIT_DIR/FETCH_HEAD` | secret commit SHA + objects |
| `refs/heads/` + `../../`×N + `etc/passwd` | `/etc/passwd` | HTTP 500, content in log |
| `refs/heads/` + `../../`×N + `nonexistent` | (missing) | HTTP 200 + error message |
