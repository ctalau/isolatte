#!/usr/bin/env python3
"""
Jenkins API Report Script
Queries a Jenkins server and reports:
- All configured jobs
- Git repository for each job
- Last build commit SHA and message
- Failure logs from the last build
"""

import re
import sys
import json
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not installed. Run: pip install requests")
    sys.exit(1)

# Configuration
JENKINS_URL = "http://localhost:8080"
JENKINS_USER = "admin"
JENKINS_API_TOKEN = "1146b379cd80f219d03088c893fb95ba16"

AUTH = (JENKINS_USER, JENKINS_API_TOKEN)


def api_get(path):
    r = requests.get(f"{JENKINS_URL}{path}", auth=AUTH)
    r.raise_for_status()
    return r.json()


def text_get(path):
    r = requests.get(f"{JENKINS_URL}{path}", auth=AUTH)
    r.raise_for_status()
    return r.text


def extract_git_repo_from_config(config_xml):
    """Extract git repo URL and branch from job config XML."""
    # Try GitSCM URL first
    url_match = re.search(r'<url>(https?://[^<]+|file://[^<]+)</url>', config_xml)
    git_repo = url_match.group(1) if url_match else None

    # Fall back to parameter default values
    if not git_repo:
        params = re.findall(r'<defaultValue>(.*?)</defaultValue>', config_xml)
        git_repo = next(
            (p for p in params if p.startswith(('https://', 'http://', 'file://'))),
            'N/A'
        )

    # Branch from GitSCM
    branch_match = re.search(r'<name>\*/(.*?)</name>', config_xml)
    if branch_match:
        git_branch = branch_match.group(1)
    else:
        params = re.findall(r'<defaultValue>(.*?)</defaultValue>', config_xml)
        git_branch = next(
            (p for p in params if p in ('master', 'main', 'develop', 'HEAD')),
            'N/A'
        )

    return git_repo, git_branch


def extract_commit_from_console(console_text):
    """Parse git commit details from build console output."""
    sha_match = re.search(r'Last commit SHA: ([a-f0-9]{40})', console_text)
    msg_match = re.search(r'Commit message: (.+)', console_text)
    author_match = re.search(r'Author: (.+)', console_text)
    date_match = re.search(r'Date: (.+)', console_text)

    return {
        "sha": sha_match.group(1) if sha_match else "N/A",
        "message": msg_match.group(1).strip() if msg_match else "N/A",
        "author": author_match.group(1).strip() if author_match else "N/A",
        "date": date_match.group(1).strip() if date_match else "N/A",
    }


def extract_failure_lines(console_text):
    """Extract lines indicating build failure from console output."""
    failure_keywords = ('ERROR', 'FAILED', 'FAILURE', 'fatal', 'BUILD FAILED')
    lines = []
    for line in console_text.split('\n'):
        stripped = line.strip()
        if stripped and any(kw in stripped for kw in failure_keywords):
            # Skip shell echo commands (lines starting with + echo)
            if not stripped.startswith('+ echo'):
                lines.append(stripped)
    return lines


def report_job(job_name):
    print(f"\n{'=' * 70}")
    print(f"  Job: {job_name}")
    print('=' * 70)

    # 1. Git repo from config
    config_xml = text_get(f"/job/{job_name}/config.xml")
    desc_match = re.search(r'<description>(.*?)</description>', config_xml)
    description = desc_match.group(1) if desc_match else "N/A"
    git_repo, git_branch = extract_git_repo_from_config(config_xml)

    print(f"  Description : {description}")
    print(f"  Git Repo    : {git_repo}")
    print(f"  Git Branch  : {git_branch}")

    # 2. Last build info
    try:
        build = api_get(f"/job/{job_name}/lastBuild/api/json")
    except Exception:
        print("  Last Build  : No builds found")
        return

    build_num = build["number"]
    build_result = build.get("result", "IN_PROGRESS")
    build_ts = datetime.fromtimestamp(build["timestamp"] / 1000).strftime('%Y-%m-%d %H:%M:%S UTC')
    duration = build.get("duration", 0) / 1000

    print(f"\n  Last Build  : #{build_num}")
    print(f"  Result      : {build_result}")
    print(f"  Started     : {build_ts}")
    print(f"  Duration    : {duration:.1f}s")

    # 3. Commit info from console
    console = text_get(f"/job/{job_name}/lastBuild/consoleText")
    commit = extract_commit_from_console(console)

    print(f"\n  Last Commit:")
    print(f"    SHA     : {commit['sha']}")
    print(f"    Message : {commit['message']}")
    print(f"    Author  : {commit['author']}")
    print(f"    Date    : {commit['date']}")

    # 4. Failure log
    failure_lines = extract_failure_lines(console)
    print(f"\n  Failure Log ({len(failure_lines)} errors):")
    if failure_lines:
        for line in failure_lines:
            print(f"    {line}")
    else:
        print("    (no failure lines detected)")


def main():
    print("=" * 70)
    print("  JENKINS API REPORT")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Server    : {JENKINS_URL}")
    print(f"  User      : {JENKINS_USER}")
    print("=" * 70)

    # List all jobs
    print("\n## Jobs")
    jobs_data = api_get("/api/json")
    jobs = jobs_data.get("jobs", [])
    print(f"  Total jobs: {len(jobs)}")
    for j in jobs:
        status = "FAILED" if j.get("color") == "red" else j.get("color", "unknown").upper()
        print(f"  [{status:^10}] {j['name']:30s}  {j['url']}")

    # Detailed report per job
    print("\n## Detailed Job Reports")
    for j in jobs:
        try:
            report_job(j["name"])
        except Exception as e:
            print(f"  Error reporting {j['name']}: {e}")

    print(f"\n{'=' * 70}")
    print("  END OF REPORT")
    print("=" * 70)


if __name__ == "__main__":
    main()
