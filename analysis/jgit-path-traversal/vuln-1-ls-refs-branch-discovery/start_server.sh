#!/usr/bin/env bash
# start_server.sh — set up the two-repo demo and start the JGit HTTP server.
#
# Usage:
#   bash start_server.sh setup    # one-time: download jars, create repos
#   bash start_server.sh serve    # start the server (blocks)
#
# Requires: Java 11+, curl
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHARED_LIB="$(cd "$SCRIPT_DIR/.." && pwd)/lib"   # shared jar cache
DEMO="/tmp/jgit-demo"

JGIT_VER="7.5.0.202512021534-r"
JETTY_VER="12.0.16"

PUBLIC_REPO="$DEMO/public.git"
SECRET_REPO="$DEMO/secret.git"
PORT=7070

# ── download ──────────────────────────────────────────────────────────────────

download_deps() {
    mkdir -p "$SHARED_LIB"
    local BASE="https://repo1.maven.org/maven2"

    echo "[*] JGit $JGIT_VER"
    curl -sSfL "$BASE/org/eclipse/jgit/org.eclipse.jgit/$JGIT_VER/org.eclipse.jgit-$JGIT_VER.jar" \
         -o "$SHARED_LIB/jgit-core.jar"
    curl -sSfL "$BASE/org/eclipse/jgit/org.eclipse.jgit.http.server/$JGIT_VER/org.eclipse.jgit.http.server-$JGIT_VER.jar" \
         -o "$SHARED_LIB/jgit-http-server.jar"

    echo "[*] Jetty $JETTY_VER"
    for MOD in server http io util session security; do
        curl -sSfL "$BASE/org/eclipse/jetty/jetty-$MOD/$JETTY_VER/jetty-$MOD-$JETTY_VER.jar" \
             -o "$SHARED_LIB/jetty-$MOD.jar"
    done
    curl -sSfL "$BASE/org/eclipse/jetty/ee10/jetty-ee10-servlet/$JETTY_VER/jetty-ee10-servlet-$JETTY_VER.jar" \
         -o "$SHARED_LIB/jetty-ee10-servlet.jar"

    echo "[*] Jakarta / SLF4J"
    curl -sSfL "$BASE/jakarta/servlet/jakarta.servlet-api/6.1.0/jakarta.servlet-api-6.1.0.jar" \
         -o "$SHARED_LIB/servlet-api.jar"
    curl -sSfL "$BASE/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar" \
         -o "$SHARED_LIB/slf4j-api.jar"
    curl -sSfL "$BASE/org/slf4j/slf4j-simple/2.0.13/slf4j-simple-2.0.13.jar" \
         -o "$SHARED_LIB/slf4j-simple.jar"

    echo "[*] Compiling JGitServer.java"
    CP=$(find "$SHARED_LIB" -name "*.jar" | tr '\n' ':')
    javac -cp "$CP" "$(cd "$SCRIPT_DIR/.." && pwd)/JGitServer.java" \
          -d "$(cd "$SCRIPT_DIR/.." && pwd)/"
}

# ── repo setup ────────────────────────────────────────────────────────────────

create_repos() {
    rm -rf "$DEMO"
    mkdir -p "$DEMO"

    # Public repo — served over HTTP
    git init --bare "$PUBLIC_REPO" -q
    local WORK="$DEMO/work-public"
    git clone "$PUBLIC_REPO" "$WORK" -q 2>/dev/null
    git -C "$WORK" config user.email "demo@example.com"
    git -C "$WORK" config user.name  "Demo"
    echo "public content" > "$WORK/readme.txt"
    git -C "$WORK" add .
    git -C "$WORK" commit --no-gpg-sign -q -m "initial public commit"
    git -C "$WORK" push -q origin master
    echo "[*] public.git: branch master with one commit"

    # Secret repo — NOT served over HTTP, lives on the same filesystem
    git init --bare "$SECRET_REPO" -q
    local WSEC="$DEMO/work-secret"
    git clone "$SECRET_REPO" "$WSEC" -q 2>/dev/null
    git -C "$WSEC" config user.email "secret@example.com"
    git -C "$WSEC" config user.name  "Secret"
    echo "TOP SECRET DATA" > "$WSEC/secret.txt"
    git -C "$WSEC" add .
    git -C "$WSEC" commit --no-gpg-sign -q -m "classified: project falcon"
    git -C "$WSEC" push -q origin master
    # Add a distinctively-named branch the attacker is trying to discover
    git -C "$WSEC" checkout -q -b classified-feature
    echo "feature data" >> "$WSEC/secret.txt"
    git -C "$WSEC" add .
    git -C "$WSEC" commit --no-gpg-sign -q -m "classified feature work"
    git -C "$WSEC" push -q origin classified-feature

    local SECRET_SHA
    SECRET_SHA=$(git -C "$WSEC" rev-parse HEAD)
    echo "[*] secret.git: branches master + classified-feature"
    echo "[*] classified-feature tip: $SECRET_SHA"
    echo ""
    echo "    The attacker does NOT know:"
    echo "      - that secret.git exists"
    echo "      - that the branch 'classified-feature' exists"
    echo "      - the SHA $SECRET_SHA"
    echo ""
    echo "    All three will be revealed by exploit.py."
}

# ── server ────────────────────────────────────────────────────────────────────

start_server() {
    CP=$(find "$SHARED_LIB" -name "*.jar" | tr '\n' ':')
    JGITSERVER="$(cd "$SCRIPT_DIR/.." && pwd)"
    echo "[*] Starting JGit HTTP server on http://localhost:$PORT/public.git"
    echo "[*] Serving: $PUBLIC_REPO"
    echo "[*] Secret (NOT served): $SECRET_REPO"
    echo ""
    exec java -cp "$JGITSERVER:$CP" JGitServer "$PUBLIC_REPO" "$PORT"
}

# ── main ──────────────────────────────────────────────────────────────────────

case "${1:-}" in
    setup)
        download_deps
        create_repos
        echo "[*] Done. Run:  bash start_server.sh serve"
        ;;
    serve)
        start_server
        ;;
    *)
        echo "Usage: bash start_server.sh [setup|serve]"
        exit 1
        ;;
esac
