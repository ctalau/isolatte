#!/usr/bin/env bash
# run_server.sh — start the vulnerable JGit HTTP server
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP=$(find "$SCRIPT_DIR/lib" -name "*.jar" | tr '\n' ':')
REPO="${1:-/tmp/jgit-vuln-demo/served.git}"
PORT="${2:-7070}"

exec java -cp "$SCRIPT_DIR:$CP" JGitServer "$REPO" "$PORT"
