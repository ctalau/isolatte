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
apt-get update
apt-get install -y --no-install-recommends openjdk-21-jdk-headless maven ca-certificates
echo "  Java: $(java -version 2>&1 | head -1)"
echo "  Maven: $(mvn --version 2>&1 | head -1)"

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
mvn dependency:resolve -B -q

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
