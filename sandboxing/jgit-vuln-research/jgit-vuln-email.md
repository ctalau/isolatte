**To:** security@eclipse.org
**Subject:** [JGit] Two Protocol V2 path traversal vulnerabilities in ProtocolV2Parser

---

Hello JGit security team,

I am reporting two path traversal vulnerabilities in JGit's Protocol V2 upload-pack
implementation, both caused by the same missing validation in `ProtocolV2Parser`. Both
allow a remote client to read data from git repositories that share a filesystem with a
JGit HTTP server but are not publicly served.

Tested version: **7.5.0.202512021534-r** (latest stable). Older releases using
`ProtocolV2Parser` are likely affected.

I am attaching proof-of-concept scripts for both. Please treat this report as confidential
until a fix is shipped.

---

## Vulnerability 1 — Branch name and SHA disclosure via `ls-refs ref-prefix`

**Severity:** High (CVSS 3.1: 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
**Config required:** None (default JGit server)
**Auth required:** No

### What an attacker can do

Send a single unauthenticated HTTP POST to any JGit smart-HTTP endpoint. The response
contains the branch names and commit SHAs of every git repository that lives on the same
filesystem and is readable by the JGit process.

**Scenario:** server hosts `/srv/git/public.git` over HTTP; `/srv/git/secret.git` is on
the same disk, not publicly served. An attacker enumerates all branches of `secret.git`
— including their names and tip SHAs — without any credentials.

### Steps to reproduce

```
bash vuln-1-ls-refs-branch-discovery/start_server.sh setup   # one-time
bash vuln-1-ls-refs-branch-discovery/start_server.sh serve   # terminal 1
python3 vuln-1-ls-refs-branch-discovery/exploit.py            # terminal 2
```

Expected output includes:

```
[3] Traversal to /tmp/jgit-demo/secret.git/refs/
    SHA                                         Leaked path
    a3f8c1d2e4b5…  refs/heads/…/secret.git/refs/heads/classified-feature
    ...

[!] Discovered branches in secret.git:
      a3f8c1d2e4b5...  refs/heads/classified-feature
```

### Root cause

`ProtocolV2Parser.parseLsRefsRequest()` appends client-supplied `ref-prefix` values to
the prefix list without validation:

```java
// ProtocolV2Parser.java
} else if (line2.startsWith("ref-prefix ")) {
    prefixes.add(line2.substring("ref-prefix ".length()));  // ← no isValidRefName()
```

These prefixes reach `RefDirectory.LooseScanner.scan()`, which builds a `java.io.File`
directly from the prefix after stripping `"refs/"`:

```java
// RefDirectory.java — LooseScanner.scan()
} else if (prefix.startsWith(R_REFS) && prefix.endsWith("/")) {
    File dir = new File(refsDir, prefix.substring(R_REFS.length()));
    //   refsDir = $GIT_DIR/refs/
    //   prefix  = "refs/heads/../../../../../../srv/git/secret.git/refs/"
    //   → new File($GIT_DIR/refs/, "heads/../../../../../../srv/git/secret.git/refs/")
    //   → OS resolves at opendir() → /srv/git/secret.git/refs/
    scanTree(prefix, dir);   // recursively lists the secret repo's refs
```

`scanTree()` returns every file whose content is a 40-char hex SHA as a ref entry in the
HTTP 200 response. No error, no log entry — the branch names and SHAs are delivered
directly to the attacker.

### Suggested fix

```java
// ProtocolV2Parser.java — parseLsRefsRequest(), before prefixes.add()
String prefix = line2.substring("ref-prefix ".length());
String check  = prefix.endsWith("/") ? prefix.substring(0, prefix.length() - 1) : prefix;
if (!check.isEmpty() && !Repository.isValidRefName(check)) {
    throw new PackProtocolException("invalid ref-prefix: " + prefix);
}
prefixes.add(prefix);
```

`Repository.isValidRefName()` already exists and rejects any name containing `..`. It is
called correctly in the receive-pack write path but not here.

---

## Vulnerability 2 — File existence oracle and commit exfiltration via `fetch/want-ref`

**Severity:** High (CVSS 3.1: 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
**Config required:** `[uploadpack] allowRefInWant = true` (non-default)
**Auth required:** No (if server allows unauthenticated access)

### What an attacker can do

When `allowRefInWant = true` is set, the `fetch` endpoint becomes a binary file-existence
oracle for any path on the server filesystem:

| HTTP response | Meaning |
|---|---|
| `200` + `ERR invalid ref name …` | File does not exist at the probed path |
| **`500`** (empty body) | File **exists** and was read; first ~4 KB in server log |
| `200` + `wanted-refs` + packfile | File contained a valid SHA; **commit exfiltrated** |

Files with git-SHA-shaped content (e.g. `FETCH_HEAD`, ref files in neighboring repos) are
served as git objects to the attacker.

### Steps to reproduce

```
bash vuln-2-want-ref-file-oracle/start_server.sh setup   # one-time
bash vuln-2-want-ref-file-oracle/start_server.sh serve   # terminal 1
python3 vuln-2-want-ref-file-oracle/exploit.py           # terminal 2
```

Expected output includes:

```
[3] File existence oracle — /etc/passwd
    HTTP : 500
    Result: EXISTS (HTTP 500 — content in server log)

[6] Secret commit exfiltration — $GIT_DIR/FETCH_HEAD
    HTTP : 200
    Result: EXFILTRATED (wanted-refs + packfile returned)
    SHA  : a3f8c1d2e4b5...
```

### Root cause

`ProtocolV2Parser.parseFetchRequest()` stores the raw `want-ref` string without
validation:

```java
// ProtocolV2Parser.java
} else if (line2.startsWith(PACKET_WANT_REF)) {
    reqBuilder.addWantedRef(line2.substring(PACKET_WANT_REF.length()));  // ← no isValidRefName()
```

`UploadPack` resolves it via `RefDirectory.fileFor()`, which has no traversal guard:

```java
// RefDirectory.java
File fileFor(String name) {
    if (name.startsWith(R_REFS)) {
        name = name.substring(R_REFS.length());   // strips "refs/"
        return new File(refsDir, name);            // ← OS resolves ".." at open()
    }
```

Path arithmetic example:

```
want-ref  "refs/heads/../../FETCH_HEAD"
fileFor:  new File($GIT_DIR/refs/, "heads/../../FETCH_HEAD")
OS:       $GIT_DIR/FETCH_HEAD   ← file read successfully
```

### Additional surface: character device files (tested live, JGit 7.5.0 / Linux kernel ≥ 5.6)

The oracle works on character devices in addition to regular files:

| `want-ref` target | HTTP | Server log | Blocks? |
|---|---|---|---|
| `/etc/passwd` | 500 | `Not a ref: …: root:x:0:0:root:/root:/bin/bash` | No |
| `/dev/urandom` | 500 | `Not a ref: …: %?…` (random bytes) | **No** |
| `/dev/random` | 500 | `Not a ref: …: M ???E,…` (random bytes) | **No** (kernel ≥ 5.6) |
| `/dev/zero` | 500 | `Not a ref: …: ` (null bytes) | **No** |
| `/dev/tty` | 200 | `PackProtocolException: Invalid ref name` | N/A — ENXIO, no tty in container |
| `/dev/stdin` | 200 | `PackProtocolException: Invalid ref name` | N/A — not accessible |

**Potential DoS via `/dev/tty`:** On non-containerized hosts where the JGit process has a
controlling terminal, `open("/dev/tty")` succeeds and `read()` blocks indefinitely. Each
such in-flight request occupies one Jetty thread. Exhausting the thread pool (default ~200
threads with 200 concurrent requests) renders the server unresponsive. This did not trigger
in the tested containerized environment (ENXIO — no controlling terminal). Deployments
launched interactively or under a process manager that allocates a pty are at risk.

**`/dev/random` on kernels < 5.6:** may block when the entropy pool is exhausted. Not
observed on the tested system (kernel ≥ 5.6 where `/dev/random` is non-blocking).

### Suggested fix

```java
// ProtocolV2Parser.java — parseFetchRequest(), before reqBuilder.addWantedRef()
String refName = line2.substring(PACKET_WANT_REF.length());
if (!Repository.isValidRefName(refName)) {
    throw new PackProtocolException(
        MessageFormat.format(JGitText.get().invalidRefName, refName));
}
reqBuilder.addWantedRef(refName);
```

---

## Common root cause

Both vulnerabilities share a single root cause: **`ProtocolV2Parser` does not call
`Repository.isValidRefName()` on client-supplied ref strings**, while `ReceivePack` (the
write path) correctly does. The fix for each surface is the same one-line guard.

The two fixes are independent and can be applied separately, but applying both in the same
commit is recommended to close the entire class of issue in `ProtocolV2Parser`.

---

## Affected files

- `org/eclipse/jgit/transport/ProtocolV2Parser.java` — two guard sites
- `org/eclipse/jgit/internal/storage/file/RefDirectory.java` — `fileFor()` trusts its
  caller; no change needed there once the parser is fixed

## Attachments

- `vuln-1-ls-refs-branch-discovery/` — README, `start_server.sh`, `exploit.py`
- `vuln-2-want-ref-file-oracle/` — README, `start_server.sh`, `exploit.py`
- `JGitServer.java` — the minimal Jetty + JGit HTTP server used by both PoCs

---

Thank you for your time. I am happy to provide a patch or additional information.

[Reporter name / affiliation]
