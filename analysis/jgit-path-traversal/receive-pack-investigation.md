# Receive-Pack Write-Side Path Traversal — Investigation

**Question:** Can `git-receive-pack` with a crafted branch name overwrite a ref
in an unserved repository at a nearby path (e.g. `/tmp/secret/`) when the served
repository is at `/tmp/public/`?

**Answer: No. The write path validates ref names; the read path does not.**

---

## Test Setup

```
/tmp/public/   ← served by JGit HTTP on :7070
/tmp/secret/   ← NOT served, same filesystem, different path
```

`/tmp/secret/refs/heads/master` contains `43ba7c6…` (a commit that is never
advertised by the public server).

---

## What Was Tried

### Attack 1 — CREATE a new ref in the secret repo

```
POST /repo.git/git-receive-pack
old: 0000000000000000000000000000000000000000
new: a9f398652cb96ed007be5fa901b3e095441e785a
ref: refs/heads/../../../../tmp/secret/refs/heads/injected
```

Result:
```
HTTP 200
[ERR] error: invalid protocol: wanted 'old new ref'
```
`/tmp/secret/refs/heads/` unchanged.

### Attack 2 — OVERWRITE the existing master in the secret repo

```
old: 43ba7c6aea4fdf86f4aceba19b67aae2fcfd38bc  (correct current SHA)
new: a9f398652cb96ed007be5fa901b3e095441e785a
ref: refs/heads/../../../../tmp/secret/refs/heads/master
```

Result:
```
HTTP 200
[ERR] error: invalid protocol: wanted 'old new ref'
```
`/tmp/secret/refs/heads/master` unchanged.

### Attack 3 — All variations tried

All `../`-containing ref names return the same error regardless of whether the
old-SHA is all-zeros (CREATE), the correct SHA (UPDATE), or any other value.

---

## Why the Write Path Is Protected

### `ReceivePack.parseCommand()` calls `isValidRefName()` — line 2027

```java
// ReceivePack.java (JGit 7.5.0), line 2010–2031
static ReceiveCommand parseCommand(String line)
        throws PackProtocolException {
    if (line == null || line.length() < 83) {
        throw new PackProtocolException(
            JGitText.get().errorInvalidProtocolWantedOldNewRef);
    }
    String oldStr = line.substring(0, 40);
    String newStr = line.substring(41, 81);
    ObjectId oldId, newId;
    try {
        oldId = ObjectId.fromString(oldStr);
        newId = ObjectId.fromString(newStr);
    } catch (InvalidObjectIdException e) {
        throw new PackProtocolException(
            JGitText.get().errorInvalidProtocolWantedOldNewRef, e);
    }
    String name = line.substring(82);              // ← client-supplied ref name
    if (!Repository.isValidRefName(name)) {        // ← validation IS present here
        throw new PackProtocolException(
            JGitText.get().errorInvalidProtocolWantedOldNewRef);
    }
    return new ReceiveCommand(oldId, newId, name);
}
```

`Repository.isValidRefName()` rejects any name where a `.` follows a `/`, `\0`,
or another `.`:

```java
// Repository.java, line 1563–1566
case '.':
    switch (p) {
    case '\0': case '/': case '.':  // ← catches "refs/heads/../" at the first '.'
        return false;
```

`refs/heads/../../../../tmp/secret/...` fails at the first `.` that appears
after a `/`, so the attack is blocked before any file I/O happens.

---

## The Asymmetry: Why the Read Path Is Vulnerable

| Path | Method | `isValidRefName()` called? | Vulnerable? |
|---|---|---|---|
| `receive-pack` push command | `ReceivePack.parseCommand()` L2027 | **YES** | No |
| `upload-pack` `want-ref` | `ProtocolV2Parser.parseFetchRequest()` | **NO** | Yes (needs `allowRefInWant`) |
| `upload-pack` `ls-refs ref-prefix` | `ProtocolV2Parser.parseLsRefsRequest()` | **NO** | Yes (default config) |

The receive-pack path added `isValidRefName()` validation; the upload-pack
Protocol V2 parsing paths did not receive the same treatment.

The error string `"error: invalid protocol: wanted 'old new ref'"` is defined in
`JGitText.properties` as `errorInvalidProtocolWantedOldNewRef` and is thrown from
`parseCommand()` on three code paths: null/short line, invalid SHA, and invalid
ref name.

---

## Conclusion

Receive-pack cannot be used to write outside the served repository's `refs/`
directory. The `isValidRefName()` guard in `ReceivePack.parseCommand()` fires
before any ref database or filesystem access.

The vulnerability is **read-only**: an unauthenticated attacker can:
- Enumerate directories outside `$GIT_DIR/refs/` (ls-refs, no config needed)
- Read SHA values from files that look like git refs (FETCH_HEAD, etc.)
- Exfiltrate commit objects whose SHA appears in those files (if objects exist)

But they **cannot write** to any ref, either in the served repo or any adjacent
repository, using the receive-pack protocol.
