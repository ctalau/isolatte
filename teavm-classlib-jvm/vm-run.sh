#!/usr/bin/env bash
# Runs a guest main class on the interpreter (org.isolatte.vm.Main) with TeaVM's class library as
# the guest's entire JRE. Usage: ./vm-run.sh [--jail DIR] [--cp EXTRA] MainClass args...
set -euo pipefail
cd "$(dirname "$0")"
M2="${M2_REPO:-$HOME/.m2/repository}"
T="$M2/org/teavm"; V=0.16.0
TEAVM="$T/teavm-classlib/$V/teavm-classlib-$V.jar:$T/teavm-core/$V/teavm-core-$V.jar:$T/teavm-interop/$V/teavm-interop-$V.jar:$T/teavm-platform/$V/teavm-platform-$V.jar:$T/teavm-jso/$V/teavm-jso-$V.jar"
XML="$M2/xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar:$M2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar"
JAIL=(); EXTRA=""
while [[ $# -gt 0 && $1 == --* ]]; do
  case $1 in
    --jail) JAIL=(--jail "$2"); shift 2 ;;
    --cp) EXTRA=":$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
exec java -cp "target/classes:$(cat target/classpath.txt)" org.isolatte.vm.Main "${JAIL[@]}" \
  --cp "work/vm-guest:$TEAVM:work/vm-gaps:$XML$EXTRA" "$@"
