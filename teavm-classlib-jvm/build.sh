#!/usr/bin/env bash
# Builds work/overlay/java.base: TeaVM's java.io, renamed to java.*, plus compatibility mixins.
set -euo pipefail
cd "$(dirname "$0")"
M2="${M2_REPO:-$HOME/.m2/repository}"
CLASSLIB="$M2/org/teavm/teavm-classlib/0.16.0/teavm-classlib-0.16.0.jar"
CORE="$M2/org/teavm/teavm-core/0.16.0/teavm-core-0.16.0.jar"
XERCES="$M2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar"

mvn -B -q package
TOOLS="target/classes:$(cat target/classpath.txt)"
rm -rf work/overlay work/mixins work/demo work/bundles work/bundles-src
mkdir -p work results

# 1. Rename. OpenJDK keeps Console (terminal/JLine plumbing) and Externalizable (serialization
#    callbacks TeaVM's interface lacks); every other TeaVM java.io class replaces OpenJDK's.
#    EXTRA_PACKAGES adds more TeaVM packages, e.g. EXTRA_PACKAGES='java/text/ java/util/regex/'.
java -cp "$TOOLS" org.isolatte.overlay.OverlayBuilder "$CLASSLIB" "$CORE" work/overlay/java.base \
  'java/io/' '!java/io/Console' '!java/io/Externalizable' ${EXTRA_PACKAGES:-}

# 2. Compile the mixins against the renamed classes, then merge them in.
javac --release 21 -nowarn -d work/mixins --patch-module java.base=work/overlay/java.base:src/compat \
  $(find src/compat -name '*.java')
java -cp "$TOOLS" org.isolatte.overlay.MixinMerger work/overlay/java.base work/mixins

# 3. Static link check against the rest of OpenJDK's java.base and Xerces.
java -cp "$TOOLS" org.isolatte.overlay.LinkChecker work/overlay/java.base "$XERCES" | tee results/link-check.txt

# 4. Demo (plain Java against standard APIs and Xerces), and Xerces' message bundles as classes:
#    boot-class-path resources are looked up through java.io, i.e. inside the jail; classes are not.
javac --release 21 -d work/demo -cp "$XERCES" $(find src/demo -name '*.java')
java -cp "$TOOLS" org.isolatte.overlay.BundleCompiler "$XERCES" org/apache/xerces/impl/msg/ work/bundles-src
javac --release 21 -nowarn -d work/bundles $(find work/bundles-src -name '*.java')
echo "built work/overlay/java.base"
