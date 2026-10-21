#!/usr/bin/env bash
# Reproduce: build resolved DITA (transtype "dita") from oxygenxml/userguide under JFR.
# Usage: profile.sh <workdir>
set -euo pipefail
W=${1:?workdir}; mkdir -p "$W"; cd "$W"
[ -d userguide ] || git clone -q --depth 1 https://github.com/oxygenxml/userguide.git
[ -d dita-ot-4.3.1 ] || { curl -sSL -o dita.zip https://github.com/dita-ot/dita-ot/releases/download/4.3.1/dita-ot-4.3.1.zip; unzip -q dita.zip; }
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -XX:StartFlightRecording:filename=$W/dita.jfr,settings=profile,jdk.ExecutionSample#period=5ms,maxsize=2g -XX:FlightRecorderOptions:stackdepth=2048 -XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints"
cd userguide
../dita-ot-4.3.1/bin/dita --input=DITA/UserManual.ditamap --format=dita \
  --filter=DITA/ditaval/editor-sa.ditaval --output=../out/resolved -v 2>&1 | python3 "$(dirname "$0")/stamp.py" > ../phases.txt
cd ..
jfr print --json --events jdk.ExecutionSample --stack-depth 2048 dita.jfr > samples2.json
python3 -I "$(dirname "$0")/analyze6.py"   # per-phase breakdown (reads samples2.json, phases.txt from cwd)
