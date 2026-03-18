#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# Maven install + Guava artifact download test
# Runs INSIDE the sandboxed container (ubuntu:24.04)
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

echo "=== Maven Install & Guava Download Test ==="
echo ""

# ── Install JDK and Maven ─────────────────────────────────────────
echo "── Installing OpenJDK 21 and Maven ──"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends openjdk-21-jdk-headless maven ca-certificates openssl
echo "  Java: $(java -version 2>&1 | head -1)"
echo "  Maven: $(mvn --version 2>&1 | head -1)"

# ── Trust upstream proxy's TLS inspection CA (if present) ─────────
# Some environments use TLS-intercepting proxies. Import their CA
# into Java's truststore so Maven HTTPS connections succeed.
echo ""
echo "── Checking for TLS inspection CA ──"
JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(which java)")")")
CACERTS="$JAVA_HOME/lib/security/cacerts"

TLS_CA=$(mktemp)
echo | openssl s_client -connect repo.maven.apache.org:443 \
  -proxy proxy:4750 -showcerts 2>/dev/null | \
  awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} n==2{print}' > "$TLS_CA"

if [ -s "$TLS_CA" ]; then
  ISSUER=$(openssl x509 -in "$TLS_CA" -noout -issuer 2>/dev/null || true)
  echo "  Found TLS inspection CA: $ISSUER"
  keytool -importcert -trustcacerts -keystore "$CACERTS" \
    -storepass changeit -noprompt -alias proxy-tls-ca \
    -file "$TLS_CA" 2>/dev/null || true
  echo "  Imported into Java truststore"
else
  echo "  No TLS inspection CA detected (direct TLS)"
fi
rm -f "$TLS_CA"

# ── Create a minimal POM that pulls Guava ─────────────────────────
WORKDIR=$(mktemp -d)
cat > "$WORKDIR/pom.xml" <<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>proxy-test</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.4.0-jre</version>
    </dependency>
  </dependencies>
</project>
XML

# ── Configure Maven to use the HTTP proxy ─────────────────────────
mkdir -p ~/.m2
cat > ~/.m2/settings.xml <<XML
<settings>
  <proxies>
    <proxy>
      <id>sandbox-proxy</id>
      <active>true</active>
      <protocol>https</protocol>
      <host>proxy</host>
      <port>4750</port>
    </proxy>
    <proxy>
      <id>sandbox-proxy-http</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>proxy</host>
      <port>4750</port>
    </proxy>
  </proxies>
</settings>
XML

# ── Resolve Guava ─────────────────────────────────────────────────
echo ""
echo "── Downloading Guava via Maven (through proxy) ──"
cd "$WORKDIR"
mvn dependency:resolve -B -U

# ── Verify the artifact landed in the local repo ──────────────────
GUAVA_JAR=$(find ~/.m2/repository/com/google/guava/guava -name 'guava-*.jar' | head -1)
if [ -z "$GUAVA_JAR" ]; then
  echo "FAIL: Guava JAR not found in local repository"
  exit 1
fi

echo ""
echo "SUCCESS: Guava downloaded → $GUAVA_JAR"
echo "  Size: $(du -h "$GUAVA_JAR" | cut -f1)"
echo ""

rm -rf "$WORKDIR"
