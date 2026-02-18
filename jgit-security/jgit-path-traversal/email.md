To: security@eclipse.org
Subject: [JGit] Two Protocol V2 path traversal vulnerabilities in ProtocolV2Parser

Hello Eclipse JGit security team,

I am reporting two path traversal vulnerabilities in JGit Protocol V2 upload-pack handling. Both issues are caused by missing ref-name validation in `ProtocolV2Parser`.

Please treat this report as confidential until a fix is released.

## Report Metadata

- Issue types:
  - Path traversal / directory traversal
  - Information disclosure
  - File existence oracle (vulnerability 2)
- Tested artifacts:
  - `org.eclipse.jgit:org.eclipse.jgit:7.5.0.202512021534-r`
  - `org.eclipse.jgit:org.eclipse.jgit.http.server:7.5.0.202512021534-r`
- Potentially affected versions:
  - Any release where `ProtocolV2Parser` accepts unvalidated `ref-prefix` or `want-ref` values and passes them to `RefDirectory` resolution.
- CVSS (initial):
  - Vulnerability 1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5 High)
  - Vulnerability 2: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5 High), with possible adjustment if non-default config requirement is weighted differently.

## Vulnerability 1: `ls-refs ref-prefix` path traversal

### 1) Type of issue

- Path traversal in Protocol V2 `ls-refs` request parsing.
- Leads to unauthorized disclosure of ref names and commit SHAs from other repositories on the same filesystem.

### 2) Affected version(s)

- Confirmed on `7.5.0.202512021534-r`.
- Older versions using the same parser path are likely affected.

### 3) Impact and exploitation

- Unauthenticated remote client can send one HTTP POST to a public repo endpoint and enumerate refs from non-served neighboring repos.
- Example impact:
  - Public repo served: `/tmp/jgit-demo/public.git`
  - Secret repo not served: `/tmp/jgit-demo/secret.git`
  - Attacker receives `refs/heads/classified-feature` and its tip SHA from `secret.git`.

### 4) Configuration required

- None. Default upload-pack Protocol V2 behavior is sufficient.

### 5) Step-by-step reproduction

1. Set up demo repos and server:
   - `bash vuln-1-ls-refs-branch-discovery/start_server.sh setup`
2. Start server:
   - `bash vuln-1-ls-refs-branch-discovery/start_server.sh serve 2> /tmp/server.log &`
3. Run exploit:
   - `python3 vuln-1-ls-refs-branch-discovery/exploit.py`
4. Observe leaked refs from `secret.git` in the HTTP response.

### 6) Location of affected source code (release/tag context)

- Release tested: `7.5.0.202512021534-r`
- Affected logic:
  - `ProtocolV2Parser.parseLsRefsRequest()` (accepts `ref-prefix` without validation)
  - `RefDirectory.LooseScanner.scan()` (constructs filesystem path from untrusted prefix)

### 7) Full paths of source files related to manifestation

- `org/eclipse/jgit/transport/ProtocolV2Parser.java`
- `org/eclipse/jgit/internal/storage/file/RefDirectory.java`

### 8) Related logs

- No specific warning/error is required for successful exploitation.
- Typical behavior is HTTP 200 with leaked ref lines in response body.

### 9) PoC / exploit code

- `vuln-1-ls-refs-branch-discovery/exploit.py`
- `vuln-1-ls-refs-branch-discovery/start_server.sh`

### 10) Root cause and minimal fix

Current behavior accepts raw `ref-prefix`:

```java
} else if (line2.startsWith("ref-prefix ")) {
    prefixes.add(line2.substring("ref-prefix ".length()));
}
```

Suggested guard before adding prefix:

```java
String prefix = line2.substring("ref-prefix ".length());
String check = prefix.endsWith("/") ? prefix.substring(0, prefix.length() - 1) : prefix;
if (!check.isEmpty() && !Repository.isValidRefName(check)) {
    throw new PackProtocolException("invalid ref-prefix: " + prefix);
}
prefixes.add(prefix);
```

## Vulnerability 2: `fetch/want-ref` path traversal oracle and log leakage

### 1) Type of issue

- Path traversal in Protocol V2 `fetch` request parsing.
- Results in a file existence oracle and server-side log disclosure.
- Content from arbitrary files can be written to server logs, exposing data to operators who may have log access but not direct filesystem access.

### 2) Affected version(s)

- Confirmed on `7.5.0.202512021534-r`.
- Older versions with same `want-ref` handling are likely affected.

### 3) Impact and exploitation

When `[uploadpack] allowRefInWant = true` is enabled:

- Attacker can probe arbitrary paths readable by server process.
- Behavior observed from HTTP responses:
  - `200` + `ERR invalid ref name ...` -> file absent
  - `500` (often empty response body) -> file exists and read/parsing path reached

Operational impact:

- For existing files with non-ref content, error text can include a prefix of file content in server logs.
- This can expose sensitive data in logs and introduce compliance/handling risks.

### 4) Configuration required

- Requires repo config:

```ini
[uploadpack]
    allowRefInWant = true
```

### 5) Step-by-step reproduction

1. Set up demo repos and server:
   - `bash vuln-2-want-ref-file-oracle/start_server.sh setup`
2. Start server:
   - `bash vuln-2-want-ref-file-oracle/start_server.sh serve 2> /tmp/server.log &`
3. Run exploit:
   - `python3 vuln-2-want-ref-file-oracle/exploit.py`
4. Observe oracle behavior (`200` absent vs `500` exists) and inspect server logs for content prefixes included in exception messages.

### 6) Location of affected source code (release/tag context)

- Release tested: `7.5.0.202512021534-r`
- Affected logic:
  - `ProtocolV2Parser.parseFetchRequest()` (accepts `want-ref` without validation)
  - `RefDirectory.fileFor()` (resolves file path from untrusted ref name)

### 7) Full paths of source files related to manifestation

- `org/eclipse/jgit/transport/ProtocolV2Parser.java`
- `org/eclipse/jgit/internal/storage/file/RefDirectory.java`

### 8) Related logs

- For existing files with non-ref content, server logs can include errors similar to:
  - `Not a ref: <refname>: <file-content-prefix>`
- This can leak portions of file content into logs while the client sees HTTP 500.

### 9) PoC / exploit code

- `vuln-2-want-ref-file-oracle/exploit.py`
- `vuln-2-want-ref-file-oracle/start_server.sh`

### 10) Root cause and minimal fix

Current behavior accepts raw `want-ref`:

```java
} else if (line2.startsWith(PACKET_WANT_REF)) {
    reqBuilder.addWantedRef(line2.substring(PACKET_WANT_REF.length()));
}
```

Suggested guard before adding wanted ref:

```java
String refName = line2.substring(PACKET_WANT_REF.length());
if (!Repository.isValidRefName(refName)) {
    throw new PackProtocolException(
        MessageFormat.format(JGitText.get().invalidRefName, refName));
}
reqBuilder.addWantedRef(refName);
```

## Common root cause

Both vulnerabilities are caused by missing `Repository.isValidRefName()` validation in Protocol V2 parser paths that consume client-controlled ref strings.

## Attachments

- `vuln-1-ls-refs-branch-discovery/` (README, setup script, exploit)
- `vuln-2-want-ref-file-oracle/` (README, setup script, exploit)
- `JGitServer.java` (minimal HTTP server used by PoCs)

I can provide a patch or test additional candidate fixes if helpful.

[Reporter name / affiliation]
