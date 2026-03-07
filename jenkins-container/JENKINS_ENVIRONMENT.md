# Jenkins Test Environment

A self-contained Jenkins CI setup that runs inside **udocker** (no root required).
Two freestyle jobs build from local git repositories and fail intentionally — used
to test build-failure log collection via the Jenkins REST API.

---

## Architecture

```
Host machine
├── /tmp/repo-alpha          ← bare-like git repo (project-alpha source)
├── /tmp/repo-beta           ← bare-like git repo (project-beta source)
├── /tmp/jenkins_home/       ← Jenkins JENKINS_HOME (persisted across restarts)
│   ├── users/admin_*/       ← admin user config + API tokens
│   ├── jobs/project-alpha/  ← job config + build history
│   └── jobs/project-beta/
└── udocker container: jenkins
    └── jenkins/jenkins:lts-jdk17 → http://localhost:8080
```

**Credentials**

| Item | Value |
|---|---|
| Jenkins URL | `http://localhost:8080` |
| Admin user | `admin` |
| Admin password | `admin123` |
| API token (example) | See `/tmp/jenkins_api_token` after setup |

---

## Quick Reproduction

### Prerequisites

| Tool | Install |
|---|---|
| `udocker` | `pip install udocker` or see [udocker docs](https://indigo-dc.github.io/udocker/) |
| `git` | system package manager |
| `curl` | system package manager |
| `python3` + `requests` | `pip install requests` |

### One-command setup

```bash
chmod +x setup-jenkins.sh
./setup-jenkins.sh
```

The script prints a summary box when done:

```
╔══════════════════════════════════════════════════════════════╗
║                  Setup Complete                             ║
╠══════════════════════════════════════════════════════════════╣
║  Jenkins UI   : http://localhost:8080                       ║
║  Username     : admin                                       ║
║  Password     : admin123                                    ║
║  API Token    : 11xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx            ║
║  Container log: /tmp/jenkins.log                            ║
║  Stop Jenkins : kill $(cat /tmp/jenkins.pid)               ║
╚══════════════════════════════════════════════════════════════╝
```

### Skip build triggers

```bash
./setup-jenkins.sh --no-build
```

---

## What the Script Does (Step by Step)

### Step 1 — Local git repos

Creates two git repositories under `/tmp/` with a short two-commit history each.

**`/tmp/repo-alpha`** (simulates a Java project with a compile error):
```
0e49955  Add feature A: isolatte module
fbe6acb  Initial commit for project-alpha
```

Files: `Main.java`, `README.md`, `feature.txt`

**`/tmp/repo-beta`** (simulates a test suite with failures):
```
9549958  Fix: resolve NullPointerException in auth module
ebfe100  Initial commit for project-beta
```

Files: `BetaTest.java`, `README.md`, `bugfix.txt`

### Step 2 — Jenkins container

```bash
udocker --allow-root pull jenkins/jenkins:lts-jdk17
udocker --allow-root create --name=jenkins jenkins/jenkins:lts-jdk17
udocker --allow-root run \
  --volume=/tmp/jenkins_home:/var/jenkins_home \
  --volume=/tmp/repo-alpha:/tmp/repo-alpha \
  --volume=/tmp/repo-beta:/tmp/repo-beta \
  --publish=8080:8080 \
  jenkins
```

The volumes make the local repos available inside the container at the same paths,
so `file:///tmp/repo-alpha` resolves correctly from inside Jenkins.

The initial setup wizard is skipped via:
- `$JENKINS_HOME/jenkins.install.UpgradeWizard.state` → `2.0`
- `$JENKINS_HOME/init.groovy.d/skip-setup.groovy`

### Step 3 — Admin user

The admin user is configured with a pre-computed **bcrypt hash** of `admin123`:

```
#jbcrypt:$2a$10$RM.16CMpXE4SMpHvj74OvuwKkk78NmlewgayvEzkb0jbiANJ0ZXsK
```

This is written directly into `$JENKINS_HOME/users/admin_*/config.xml`, avoiding
the need to install bcrypt on the host.

### Step 4 — Jobs

Two freestyle jobs are created via `POST /createItem` with an XML config:

| Job | Git URL | Branch | Build result |
|---|---|---|---|
| `project-alpha` | `file:///tmp/repo-alpha` | `master` | FAILURE (exit 1) |
| `project-beta` | `file:///tmp/repo-beta` | `master` | FAILURE (exit 1) |

Build shell command (same for both):
```bash
echo "Build started"
git log -1 --format="Last commit SHA: %H%nCommit message: %s%nAuthor: %an%nDate: %cd" \
  --date=format:'%Y-%m-%d %H:%M:%S UTC' || echo "no git"
echo "---"
echo "Simulating build failure..."
exit 1
```

The `exit 1` is intentional — it lets `jenkins_api_report.py` demonstrate failure
log extraction without requiring a real compilation or test suite.

### Step 5 — API token

Generated via:
```
POST /user/admin/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken
```

Token is saved to `/tmp/jenkins_api_token` for use by other scripts.

### Step 6 — Build triggers (optional)

```
POST /job/project-alpha/build
POST /job/project-beta/build
```

---

## Running the API Report

After setup, query Jenkins and get a structured report:

```bash
python3 jenkins_api_report.py
```

Example output:
```
======================================================================
  JENKINS API REPORT
  Generated : 2026-03-05 12:00:00
  Server    : http://localhost:8080
======================================================================

## Jobs
  Total jobs: 2
  [  FAILED  ] project-alpha     http://localhost:8080/job/project-alpha/
  [  FAILED  ] project-beta      http://localhost:8080/job/project-beta/

## Detailed Job Reports

======================================================================
  Job: project-alpha
======================================================================
  Git Repo    : file:///tmp/repo-alpha
  Git Branch  : master

  Last Build  : #1
  Result      : FAILURE
  Started     : 2026-03-05 12:00:10 UTC
  Duration    : 4.8s

  Last Commit:
    SHA     : 0e499550d1aa6deed1c0eb95f9b079e0922c72f6
    Message : Add feature A: isolatte module

  Failure Log (2 errors):
    ERROR: Cannot find symbol: isolatte.security.Sandbox
    BUILD FAILED
```

---

## Managing the Container

```bash
# View live Jenkins log
tail -f /tmp/jenkins.log

# Stop Jenkins
kill $(cat /tmp/jenkins.pid)

# Restart (reuses the same JENKINS_HOME — all config is preserved)
udocker --allow-root run \
  --volume=/tmp/jenkins_home:/var/jenkins_home \
  --volume=/tmp/repo-alpha:/tmp/repo-alpha \
  --volume=/tmp/repo-beta:/tmp/repo-beta \
  --publish=8080:8080 \
  jenkins > /tmp/jenkins.log 2>&1 &
echo $! > /tmp/jenkins.pid

# Full teardown
kill $(cat /tmp/jenkins.pid) 2>/dev/null || true
rm -rf /tmp/jenkins_home /tmp/repo-alpha /tmp/repo-beta /tmp/jenkins.log /tmp/jenkins.pid
```

---

## Troubleshooting

### Jenkins never becomes ready

Check the log for errors:
```bash
tail -50 /tmp/jenkins.log
```

Common causes:
- Port 8080 already in use → `lsof -i :8080` to find the occupant
- udocker container not found → `udocker --allow-root ps`

### HTTP 403 on API calls

Jenkins requires a CSRF crumb for POST requests. The setup script fetches one
automatically. If you call the API manually:

```bash
# Fetch crumb
CRUMB=$(curl -s -u admin:admin123 \
  http://localhost:8080/crumbIssuer/api/json | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  print(d['crumbRequestField']+':'+d['crumb'])")

# Use it in subsequent POSTs
curl -X POST -u admin:admin123 -H "$CRUMB" \
  http://localhost:8080/job/project-alpha/build
```

### Jobs not visible in UI

The git plugin must be installed. On `lts-jdk17` it is included by default.
If it is missing, install it via:
```bash
curl -X POST -u admin:admin123 -H "$CRUMB" \
  "http://localhost:8080/pluginManager/install?plugin.git.default=on&dynamicLoad=true"
```

### `file://` URL not resolving

Make sure the repos are mounted into the container.
The `setup-jenkins.sh` script passes `--volume=/tmp/repo-alpha:/tmp/repo-alpha` for this reason.
If you started the container manually without those volume flags, the `file://` paths
will be invisible to Jenkins. Restart with the correct flags.

---

## Files in This Repository

| File | Purpose |
|---|---|
| `setup-jenkins.sh` | End-to-end setup script (this document's companion) |
| `jenkins_api_report.py` | Queries Jenkins REST API and prints a build report |
| `JENKINS_ENVIRONMENT.md` | This document |
