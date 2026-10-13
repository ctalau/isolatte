#!/usr/bin/env bash
# Small-file performance: sample/jail/main.xml (230 bytes + 2 XIncludes: one XML, one text).
# Process wall time = fork+exec+parse+exit, mean of N runs. In-process numbers come from the binary itself.
set -euo pipefail
cd "$(dirname "$0")"
N=${N:-300}; W=${W:-5000}
J=$PWD/sample/jail
CP=$HOME/.m2/repository/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar:$HOME/.m2/repository/xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar
mkdir -p target/jvm && javac -cp "$CP" -d target/jvm bench/JvmBench.java 2>&1 | grep -v '^Picked' || true
wall() { # label cmd... : mean/min wall ms over N fresh processes
  local label=$1; shift
  python3 - "$N" "$label" "$@" <<'P'
import subprocess, sys, time, statistics
n = int(sys.argv[1]); label = sys.argv[2]; cmd = sys.argv[3:]
ts = []
for _ in range(n):
    t = time.perf_counter(); subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); ts.append((time.perf_counter() - t) * 1000)
ts.sort()
print(f"{label:46s} median {statistics.median(ts):7.2f} ms  p95 {ts[int(n*.95)-1]:7.2f} ms  min {ts[0]:7.2f} ms  (n={n})")
P
}
echo "## fresh-process wall time, parse of file:///main.xml"
echo "# baseline: spawn /bin/true"; wall "fork+exec /bin/true" /bin/true
wall "TeaVM C, jailed, dynamic libc" target/xi "$J" file:///main.xml
wall "TeaVM C, NOT jailed, dynamic libc" target/xi --no-jail / "file://$J/main.xml"
wall "HotSpot 21 (-Xshare:auto), plain Xerces" java -cp "target/jvm:$CP" JvmBench 0 "file://$J/main.xml"
wall "HotSpot 21 (-XX:TieredStopAtLevel=1 -Xshare:auto)" java -XX:TieredStopAtLevel=1 -cp "target/jvm:$CP" JvmBench 0 "file://$J/main.xml"
echo; echo "## in-process: first (cold) parse, then $W warm parses"
echo "# TeaVM C jailed";     target/xi --bench "$W" "$J" file:///main.xml | grep -a "parse"
echo "# TeaVM C NOT jailed"; target/xi --no-jail --bench "$W" / "file://$J/main.xml" | grep -a "parse"
echo "# HotSpot 21";         java -cp "target/jvm:$CP" JvmBench "$W" "file://$J/main.xml" 2>&1 | grep -a "parse"
