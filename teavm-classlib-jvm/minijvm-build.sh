#!/usr/bin/env bash
# Builds miniJVM (pinned upstream commit + minijvm/minijvm.patch + minijvm/jni_teavm.c) and the boot
# class path jar that makes TeaVM's class library its entire JRE (org.isolatte.minijvm.RuntimeBuilder).
# Needs network access the first time (git fetch of miniJVM), a C compiler, CMake, JDK 21, Maven.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
M2="${M2_REPO:-$HOME/.m2/repository}"
T="$M2/org/teavm"; V=0.16.0
CLASSLIB="$T/teavm-classlib/$V/teavm-classlib-$V.jar"
TEAVM_JARS="$CLASSLIB $T/teavm-core/$V/teavm-core-$V.jar $T/teavm-interop/$V/teavm-interop-$V.jar
  $T/teavm-platform/$V/teavm-platform-$V.jar $T/teavm-jso/$V/teavm-jso-$V.jar
  $T/teavm-jso-apis/$V/teavm-jso-apis-$V.jar $T/teavm-jso-impl/$V/teavm-jso-impl-$V.jar"
XERCES="$M2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar"
XML_APIS="$M2/xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar"
MINIJVM_REPO=https://github.com/digitalgust/miniJVM.git
MINIJVM_COMMIT=87c9808145fabbf13c7a0d6b6d1e5bfbdbdba5a8
W=work/minijvm
mkdir -p "$W"

# 1. miniJVM at a pinned commit, patched.
if [ ! -d "$W/src/.git" ]; then
  git init -q "$W/src"
  git -C "$W/src" remote add origin "$MINIJVM_REPO"
fi
if ! git -C "$W/src" cat-file -e "$MINIJVM_COMMIT^{commit}" 2>/dev/null; then
  git -C "$W/src" fetch -q --depth 1 origin "$MINIJVM_COMMIT"
fi
git -C "$W/src" checkout -q -f "$MINIJVM_COMMIT"
git -C "$W/src" clean -fdq
git -C "$W/src" apply "$HERE/minijvm/minijvm.patch"
cp minijvm/jni_teavm.c "$W/src/minijvm/c/jvm/"
cmake -S "$W/src/minijvm/c" -B "$W/cmake" -DCMAKE_BUILD_TYPE=Release > /dev/null
cmake --build "$W/cmake" -j"$(nproc)" --target mini_jvm > /dev/null
cp "$W/src/binary/centos_x64/mini_jvm" "$W/mini_jvm"

# 2. The runtime builder.
mvn -B -q package
TOOLS="target/classes:$(cat target/classpath.txt)"

# 3. TeaVM's classes, renamed as TeaVM's compiler does.
rm -rf "$W/renamed" "$W/mixins" work/vm-guest work/vm-gaps work/demo
java -cp "$TOOLS" org.isolatte.minijvm.RuntimeBuilder rename "$W/renamed" $TEAVM_JARS

# 4. Guest code: support classes, java.* gap classes, the demo. Compiled against OpenJDK's API (javac
#    needs one), run against TeaVM's. Mixins compile against the renamed TeaVM classes.
javac --release 21 -nowarn -d work/vm-guest -cp "$T/teavm-core/$V/teavm-core-$V.jar:$T/teavm-platform/$V/teavm-platform-$V.jar" \
  $(find src/vm-guest -name '*.java')
javac -nowarn -d work/vm-gaps --patch-module java.base=src/vm-gaps $(find src/vm-gaps -name '*.java')
javac --release 21 -nowarn -d work/demo -cp "$XERCES" $(find src/demo -name '*.java')
javac -nowarn -d "$W/mixins" --patch-module java.base="$W/renamed":src/minijvm-mixins \
  --add-reads java.base=ALL-UNNAMED -cp work/vm-guest $(find src/minijvm-mixins -name '*.java')

# 5. The boot class path jar.
java -cp "$TOOLS" org.isolatte.minijvm.RuntimeBuilder assemble "$W/boot.jar" "$W/renamed" "$W/mixins" \
  "work/vm-guest:work/vm-gaps:$XML_APIS:$XERCES:work/demo" "$CLASSLIB" | grep -v '^  metadata'
echo "built $W/mini_jvm and $W/boot.jar"
