#!/usr/bin/env bash
# Builds the interpreter (org.isolatte.vm, in target/classes), the guest support classes
# (work/vm-guest: jailed VFS, file: URL handler), gap classes (work/vm-gaps) and the demo (work/demo).
set -euo pipefail
cd "$(dirname "$0")"
M2="${M2_REPO:-$HOME/.m2/repository}"
CORE="$M2/org/teavm/teavm-core/0.16.0/teavm-core-0.16.0.jar"
XERCES="$M2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar"
mvn -B -q package
rm -rf work/vm-guest work/vm-gaps work/demo
# Guest code is compiled against OpenJDK's API (javac needs one) but runs against TeaVM's.
javac --release 21 -nowarn -d work/vm-guest -cp "$CORE" $(find src/vm-guest -name '*.java')
# java.* classes TeaVM's class library lacks (each one listed in the README).
javac -nowarn -d work/vm-gaps --patch-module java.base=src/vm-gaps $(find src/vm-gaps -name '*.java')
javac --release 21 -d work/demo -cp "$XERCES" $(find src/demo -name '*.java')
echo "built target/classes (VM), work/vm-guest, work/demo"
