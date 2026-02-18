#!/usr/bin/env bash
# setup.sh — download dependencies and prepare the test repository
# Tested on Ubuntu 24.04 with Java 21 and Maven 3.9.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$SCRIPT_DIR/lib"
DEMO="/tmp/jgit-vuln-demo"
JGIT_VER="7.5.0.202512021534-r"
JETTY_VER="12.0.16"

mkdir -p "$LIB"

echo "[*] Downloading JGit $JGIT_VER..."
curl -sL "https://repo1.maven.org/maven2/org/eclipse/jgit/org.eclipse.jgit/${JGIT_VER}/org.eclipse.jgit-${JGIT_VER}.jar" \
     -o "$LIB/jgit-core.jar"
curl -sL "https://repo1.maven.org/maven2/org/eclipse/jgit/org.eclipse.jgit.http.server/${JGIT_VER}/org.eclipse.jgit.http.server-${JGIT_VER}.jar" \
     -o "$LIB/jgit-http-server.jar"

echo "[*] Downloading Jetty $JETTY_VER..."
for MOD in server http io util session security; do
    curl -sL "https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-${MOD}/${JETTY_VER}/jetty-${MOD}-${JETTY_VER}.jar" \
         -o "$LIB/jetty-${MOD}.jar"
done
curl -sL "https://repo1.maven.org/maven2/org/eclipse/jetty/ee10/jetty-ee10-servlet/${JETTY_VER}/jetty-ee10-servlet-${JETTY_VER}.jar" \
     -o "$LIB/jetty-ee10-servlet.jar"

echo "[*] Downloading Jakarta Servlet API and SLF4J..."
curl -sL "https://repo1.maven.org/maven2/jakarta/servlet/jakarta.servlet-api/6.1.0/jakarta.servlet-api-6.1.0.jar" \
     -o "$LIB/servlet-api.jar"
curl -sL "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar" \
     -o "$LIB/slf4j-api.jar"
curl -sL "https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/2.0.13/slf4j-simple-2.0.13.jar" \
     -o "$LIB/slf4j-simple.jar"

echo "[*] Compiling JGitServer..."
CP=$(find "$LIB" -name "*.jar" | tr '\n' ':')
javac -cp "$CP" "$SCRIPT_DIR/JGitServer.java" -d "$SCRIPT_DIR/"

echo "[*] Setting up demo repository at $DEMO..."
rm -rf "$DEMO"
mkdir -p "$DEMO"

git init --bare "$DEMO/served.git"

git clone "$DEMO/served.git" "$DEMO/working" 2>&1 | tail -1
cd "$DEMO/working"
git config user.email "demo@example.com"
git config user.name  "Demo"
git config commit.gpgSign false

echo "public" > public.txt
git add . && git commit --no-gpg-sign -m "public commit"
git push origin master

# Create a secret commit that is NEVER pushed to served.git
git checkout -b secret-branch
echo "TOP SECRET DATA" > secret.txt
git add . && git commit --no-gpg-sign -m "secret commit never pushed"
SECRET_SHA=$(git rev-parse HEAD)
echo "[*] Secret commit SHA: $SECRET_SHA"

# Simulate the SHA being stored in FETCH_HEAD of the served bare repo
# (this happens naturally after any server-side git operation, e.g. a CI
# pipeline fetching from another remote into the same bare repo)
echo "${SECRET_SHA}	not-for-merge	branch 'secret-branch'" \
    > "$DEMO/served.git/FETCH_HEAD"

# Enable the want-ref attack surface
cat >> "$DEMO/served.git/config" << EOF

[uploadpack]
    allowRefInWant = true
EOF

echo ""
echo "[*] Setup complete."
echo "[*] FETCH_HEAD: $(cat $DEMO/served.git/FETCH_HEAD)"
echo ""
echo "Start the server with:"
echo "  ./run_server.sh"
