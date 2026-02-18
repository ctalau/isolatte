# How to Report

## Channel

**Preferred:** open a confidential issue at
https://gitlab.eclipse.org/security/vulnerability-reports
(tick the *Confidential* checkbox on the issue form).

**Fallback:** email security@eclipse.org — PGP key at https://www.eclipse.org/security/

Do not open a public GitLab/GitHub issue before a fix is released.

## What to send

Send `email.md` as the body and attach the two report folders + `JGitServer.java`.

## CVSS 3.1

Both vulnerabilities:
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — **Base score 7.5 (High)**

For Vuln 2, reviewers may raise AC to Medium (non-default config required), giving **6.5**.

## Timeline

Eclipse targets 90-day coordinated disclosure. A CVE can be requested from Eclipse or
MITRE once the team acknowledges the report.
