# How to Report These Vulnerabilities to the JGit Maintainers

JGit is an Eclipse Foundation project. Eclipse has a defined, confidential security
disclosure process. **Do not open a public GitLab/GitHub issue.** Doing so gives attackers
a head start before a fix is shipped.

---

## Step 1 — Report via the Eclipse Vulnerability Tracker (preferred)

Eclipse Foundation operates a private GitLab group for security reports:

> **https://gitlab.eclipse.org/security/vulnerability-reports**

1. Sign in with your Eclipse Foundation account (free to create).
2. Open a **new issue** in the `vulnerability-reports` project.
3. Mark the issue **Confidential** (the checkbox on the issue form).
4. Fill in the template fields — particularly:
   - **Affected project:** Eclipse JGit (`org.eclipse.jgit`)
   - **Affected versions:** ≤ 7.5.0.202512021534-r (latest stable, Feb 2026)
   - **Severity:** High (CVSS 3.1 suggested below)
5. Attach or paste the relevant README and PoC script from each report folder.

The security team will acknowledge within 5 business days and coordinate a CVE assignment
and fix timeline with the JGit committers.

---

## Step 2 — Email fallback

If the GitLab tracker is unavailable or you prefer email:

> **security@eclipse.org**

Use PGP encryption if possible. The public key is at:
https://www.eclipse.org/security/

Subject line suggestion:
```
[JGit] Protocol V2 path traversal in ProtocolV2Parser — two attack surfaces
```

---

## What to Include in the Report

Copy the structure below for each vulnerability.

```
## Summary
One sentence: what, where, impact.

## Affected component
org.eclipse.jgit — ProtocolV2Parser (parseLsRefsRequest / parseFetchRequest)
org.eclipse.jgit.internal.storage.file — RefDirectory.LooseScanner / fileFor()

## Affected versions
JGit ≤ 7.5.0.202512021534-r (tested; older versions likely affected)

## Severity (CVSS 3.1)
[see below]

## Steps to reproduce
1. bash start_server.sh setup
2. bash start_server.sh serve   (separate terminal)
3. python3 exploit.py

## Expected result
Branch names / file existence / commit SHA of the secret repo returned.

## Root cause
ProtocolV2Parser does not call Repository.isValidRefName() before storing
client-supplied ref strings. [paste relevant code snippet]

## Suggested fix
[paste the one-line guard from the README]

## Reporter
Your name / handle / affiliation (optional but appreciated).
```

---

## CVSS 3.1 Scores

### Vuln 1 — ls-refs ref-prefix path traversal

| Metric | Value | Reason |
|---|---|---|
| Attack Vector | Network | HTTP request, no local access needed |
| Attack Complexity | Low | Single crafted request, no race or pre-condition |
| Privileges Required | None | No authentication in default config |
| User Interaction | None | Server-side processing only |
| Scope | Unchanged | JGit process boundary not crossed |
| Confidentiality | High | Branch names and commit SHAs of adjacent repos disclosed |
| Integrity | None | Read-only attack |
| Availability | None | No DoS component |

**Base Score: 7.5 (High)**
Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

### Vuln 2 — want-ref file existence oracle

| Metric | Value | Reason |
|---|---|---|
| Attack Vector | Network | HTTP request |
| Attack Complexity | Low | Single crafted request |
| Privileges Required | None | No authentication |
| User Interaction | None | |
| Scope | Unchanged | |
| Confidentiality | High | File existence, file content in logs, secret commit exfiltrated |
| Integrity | None | Read-only |
| Availability | None | |

**Base Score: 7.5 (High)**
Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

Note: `allowRefInWant = true` is a non-default prerequisite for Vuln 2; some scorers
may raise Attack Complexity to Medium, giving a base score of **6.5 (Medium)**.

---

## Timeline expectation

Eclipse Foundation targets a 90-day coordinated disclosure window from first contact to
public advisory, but will coordinate with reporters on timing. Request a CVE from Eclipse
or from MITRE directly once the maintainers acknowledge the report.

---

## References

- Eclipse Security policy: https://www.eclipse.org/security/
- JGit project: https://projects.eclipse.org/projects/technology.jgit
- JGit source (Gerrit): https://git.eclipse.org/r/jgit/jgit
- Responsible disclosure best practices: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html
