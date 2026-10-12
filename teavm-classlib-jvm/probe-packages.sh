#!/usr/bin/env bash
# Boots HotSpot with one raw TeaVM package (renamed, no mixins) patched into java.base and runs a
# hello-world. Shows which parts of TeaVM's class library HotSpot accepts at all. Run ./build.sh first.
set -uo pipefail
cd "$(dirname "$0")"
M2="${M2_REPO:-$HOME/.m2/repository}"
CLASSLIB="$M2/org/teavm/teavm-classlib/0.16.0/teavm-classlib-0.16.0.jar"
CORE="$M2/org/teavm/teavm-core/0.16.0/teavm-core-0.16.0.jar"
TOOLS="target/classes:$(cat target/classpath.txt)"
mkdir -p work/probe/hello results
javac --release 21 -d work/probe/hello src/probe/Hello.java
{
  echo "| TeaVM package (raw, alone) | HotSpot result |"
  echo "| --- | --- |"
  for p in 'java/**' java/lang/ java/lang/annotation/ java/lang/invoke/ java/lang/ref/ java/lang/reflect/ \
      java/io/ java/math/ java/net/ java/net/impl/ java/nio/ java/nio/channels/ 'java/nio/charset/**' \
      'java/nio/file/**' java/security/ java/text/ java/util/ 'java/util/concurrent/**' java/util/function/ \
      java/util/jar/ java/util/logging/ java/util/random/ java/util/regex/ 'java/util/stream/**' java/util/zip/ \
      java/awt/; do
    d="work/probe/$(echo "$p" | tr '/*' '__')"
    rm -rf "$d"
    java -cp "$TOOLS" org.isolatte.overlay.OverlayBuilder "$CLASSLIB" "$CORE" "$d" "$p" > /dev/null
    out=$(timeout 60 java -Xshare:off --patch-module java.base="$d" -cp work/probe/hello Hello 2>&1 \
      | grep -v '^Picked up JAVA_TOOL_OPTIONS' | grep -v 'Compiler intrinsic' | grep -v '^\[' \
      | grep -v '^Error occurred during initialization' | head -1 | cut -c1-150 | sed 's/|/\\|/g')
    case "$out" in "hello [1, 2, 3] x") out="boots, hello-world OK";; esac
    echo "| \`$p\` | $out |"
  done
} | tee results/package-probe.md
