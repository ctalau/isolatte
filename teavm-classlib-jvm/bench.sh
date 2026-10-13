#!/usr/bin/env bash
# Performance comparison of the ways this experiment runs Java code:
#   hotspot          stock OpenJDK 21 (JIT), OpenJDK class library        - reference
#   hotspot-xint     stock OpenJDK 21, interpreter only (-Xint)          - reference interpreter
#   hotspot-teavmio  HotSpot + TeaVM java.io overlay, jailed (variant 1)
#   interp           this experiment's own bytecode interpreter (commit 9b463e2, restored from git)
#   interp-c1        the same with the host JVM limited to C1 (-XX:TieredStopAtLevel=1)
#   minijvm          miniJVM + TeaVM class library, jailed (variant 2), JIT on (default)
#   minijvm-nojit    the same, built with JIT_ENABLE 0
# Workloads: Hello (startup), XIncludeDemo (5 documents), XmlBench (parse a ~400 KB document with an
# XInclude N times), CpuBench (sieve, HashMap, StringBuilder, sort). Run ./build.sh and
# ./minijvm-build.sh first. Writes results/bench.md and results/bench-raw.txt.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$(pwd)"
M2="${M2_REPO:-$HOME/.m2/repository}"
T="$M2/org/teavm"; V=0.16.0
XERCES="$M2/xerces/xercesImpl/2.12.2/xercesImpl-2.12.2.jar"
XML_APIS="$M2/xml-apis/xml-apis/1.4.01/xml-apis-1.4.01.jar"
TEAVM="$T/teavm-classlib/$V/teavm-classlib-$V.jar:$T/teavm-core/$V/teavm-core-$V.jar:$T/teavm-interop/$V/teavm-interop-$V.jar:$T/teavm-platform/$V/teavm-platform-$V.jar:$T/teavm-jso/$V/teavm-jso-$V.jar"
TOOLS="target/classes:$(cat target/classpath.txt)"
B=work/bench
XML_ROUNDS=${XML_ROUNDS:-10}
CPU_ROUNDS=${CPU_ROUNDS:-5}
CPU_SIZE=${CPU_SIZE:-20000}
mkdir -p "$B"

# --- workloads
rm -rf "$B/classes" && javac --release 21 -nowarn -d "$B/classes" -cp "$XERCES" $(find src/bench -name '*.java')
rm -rf "$B/jail" && mkdir -p "$B/jail"
python3 - "$B/jail" <<'PY'
import sys
d = sys.argv[1]
with open(d + "/part.xml", "w") as f:
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<part>' + "".join(
        f'<p n="{i}">included paragraph {i}</p>' for i in range(500)) + '</part>\n')
with open(d + "/big.xml", "w") as f:
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<catalog xmlns:xi="http://www.w3.org/2001/XInclude">\n')
    for i in range(4000):
        f.write(f'  <item id="i{i}" price="{i * 0.25:.2f}"><name>Item number {i}</name><tags><t>a</t><t>b{i % 7}</t></tags></item>\n')
    f.write('  <xi:include href="part.xml"/>\n</catalog>\n')
PY

# --- miniJVM boot jar with the benchmarks, and an interpreter-only miniJVM
java -cp "$TOOLS" org.isolatte.minijvm.RuntimeBuilder assemble "$B/boot.jar" work/minijvm/renamed work/minijvm/mixins \
  "work/vm-guest:work/vm-gaps:$XML_APIS:$XERCES:work/demo:$B/classes" "$T/teavm-classlib/$V/teavm-classlib-$V.jar" > /dev/null
if [ ! -x "$B/nojit/binary/centos_x64/mini_jvm" ]; then
  rm -rf "$B/nojit" && mkdir -p "$B/nojit/minijvm"
  cp -r work/minijvm/src/minijvm/c "$B/nojit/minijvm/c"
  sed -i 's/^#define JIT_ENABLE 01$/#define JIT_ENABLE 0/' "$B/nojit/minijvm/c/jvm/jit.h"
  grep -q '^#define JIT_ENABLE 0$' "$B/nojit/minijvm/c/jvm/jit.h"
  cmake -S "$B/nojit/minijvm/c" -B "$B/nojit/cmake" -DCMAKE_BUILD_TYPE=Release > /dev/null
  cmake --build "$B/nojit/cmake" -j"$(nproc)" --target mini_jvm > /dev/null
fi

# --- this experiment's interpreter, as it was in commit 9b463e2
if [ ! -d "$B/interp/classes" ]; then
  rm -rf "$B/interp" && mkdir -p "$B/interp/src"
  git -C .. archive 9b463e2 teavm-classlib-jvm/src/main/java/org/isolatte/vm | tar -x -C "$B/interp/src"
  javac --release 21 -nowarn -d "$B/interp/classes" -cp "$TOOLS" $(find "$B/interp/src" -name '*.java')
fi

JAIL="$HERE/$B/jail"
DEMO_JAIL="$HERE/work/sample/jail"
run() { # run CONFIG JAIL MAIN ARGS... ; MAIN args use file:/// URIs inside the jail
  local cfg=$1 jail=$2; shift 2
  case $cfg in
    hotspot|hotspot-xint)
      local args=() a
      for a in "$@"; do args+=("${a/file:\/\/\//file://$jail/}"); done
      local x=(); [ "$cfg" = hotspot-xint ] && x=(-Xint)
      java "${x[@]}" -cp "$XERCES:work/demo:work/vm-guest:$B/classes" "${args[@]}" ;;
    hotspot-teavmio)
      java -Xshare:off --patch-module java.base=work/overlay/java.base \
        -Xbootclasspath/a:"$XERCES":work/bundles:work/demo:work/vm-guest:"$B/classes" \
        -Djdk.internal.io.vfs.root="$jail" "$@" ;;
    interp|interp-c1)
      local h=(); [ "$cfg" = interp-c1 ] && h=(-XX:TieredStopAtLevel=1)
      java "${h[@]}" -cp "$B/interp/classes:$TOOLS" org.isolatte.vm.Main --jail "$jail" \
        --cp "work/vm-guest:$TEAVM:work/vm-gaps:$XML_APIS:$XERCES:work/demo:$B/classes" "$@" ;;
    minijvm|minijvm-nojit)
      local bin=work/minijvm/mini_jvm; [ "$cfg" = minijvm-nojit ] && bin="$B/nojit/binary/centos_x64/mini_jvm"
      ISOLATTE_JAIL="$jail" "$bin" -bootclasspath "$HERE/$B/boot.jar" -cp "$HERE/$B/boot.jar" org.isolatte.guest.Boot "$@" ;;
  esac
}

CONFIGS="hotspot hotspot-xint hotspot-teavmio interp interp-c1 minijvm minijvm-nojit"
DOCS="file:///main.xml file:///escape-dotdot.xml file:///escape-absolute.xml file:///escape-symlink.xml file:///escape-fallback.xml"
[ -f work/sample/jail/escape-absolute.xml ] || ./minijvm-verify.sh > /dev/null # creates the demo jail
RAW=results/bench-raw.txt
: > "$RAW"
for cfg in $CONFIGS; do
  for w in hello demo xml cpu; do
    case $w in
      hello) set -- org.isolatte.guest.Hello x; j=$DEMO_JAIL ;;
      demo) set -- org.isolatte.demo.XIncludeDemo $DOCS; j=$DEMO_JAIL ;;
      xml) set -- org.isolatte.bench.XmlBench file:///big.xml "$XML_ROUNDS"; j=$JAIL ;;
      cpu) set -- org.isolatte.bench.CpuBench "$CPU_ROUNDS" "$CPU_SIZE"; j=$JAIL ;;
    esac
    reps=1; [ $w = hello ] || [ $w = demo ] && reps=3
    for rep in $(seq $reps); do
      s=$(date +%s%N)
      out=$(run "$cfg" "$j" "$@" 2>&1 | grep -v '^Picked up JAVA_TOOL_OPTIONS\|^\[INFO\]\|^method not exist' || true)
      e=$(date +%s%N)
      echo "=== $cfg $w rep$rep wall_ms=$(( (e - s) / 1000000 ))" >> "$RAW"
      printf '%s\n' "$out" | sed "s#$HERE#<experiment>#g" >> "$RAW"
    done
    echo "done $cfg $w" >&2
  done
done

python3 - "$RAW" "$XML_ROUNDS" "$CPU_ROUNDS" "$CPU_SIZE" > results/bench.md <<'PY'
import re, statistics, sys, platform, os
raw, xml_rounds, cpu_rounds, cpu_size = sys.argv[1:]
runs = {}
cur = None
for line in open(raw, encoding="utf-8"):
    m = re.match(r"=== (\S+) (\S+) rep(\d+) wall_ms=(\d+)", line)
    if m:
        cur = runs.setdefault((m[1], m[2]), {"wall": [], "rounds": [], "out": []})
        cur["wall"].append(int(m[4]))
        cur["rounds_this"] = []
        continue
    cur["out"].append(line.rstrip("\n"))
    r = re.match(r"round (\d+): (\d+) ms", line)
    if r:
        cur["rounds"].append(int(r[2]))
configs = ["hotspot", "hotspot-xint", "hotspot-teavmio", "interp", "interp-c1", "minijvm", "minijvm-nojit"]
names = {"hotspot": "HotSpot (JIT), OpenJDK library", "hotspot-xint": "HotSpot -Xint, OpenJDK library",
         "hotspot-teavmio": "HotSpot + TeaVM java.io (variant 1)", "interp": "own interpreter + TeaVM library", "interp-c1": "own interpreter, host C1 only",
         "minijvm": "miniJVM (JIT) + TeaVM library", "minijvm-nojit": "miniJVM (no JIT) + TeaVM library"}
def get(c, w):
    return runs.get((c, w))
def ok(c, w, needle):
    d = get(c, w)
    return d is not None and any(needle in l for l in d["out"])
print("# Benchmark results\n")
print(f"Machine: {os.cpu_count()} vCPU, {platform.platform()}. Produced by `./bench.sh`; raw output in [bench-raw.txt](bench-raw.txt).\n")
print("Wall times include VM startup (median of 3 runs for Hello and the demo, one run otherwise). "
      f"XmlBench parses a ~400 KB document with one XInclude {xml_rounds} times; CpuBench runs {cpu_rounds} rounds at size {cpu_size}. "
      "*First* is the first round inside the guest (cold), *best* the fastest later round (warm).\n")
print("| Configuration | Hello wall | Demo wall | XmlBench first | XmlBench best | XmlBench wall | CpuBench first | CpuBench best | CpuBench wall |")
print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
def ms(v):
    return "–" if v is None else (f"{v / 1000:.2f} s" if v >= 1000 else f"{v} ms")
for c in configs:
    row = [names[c]]
    for w in ["hello", "demo"]:
        d = get(c, w)
        row.append(ms(int(statistics.median(d["wall"]))) if d else "–")
    for w in ["xml", "cpu"]:
        d = get(c, w)
        if not d or not d["rounds"]:
            row += ["failed", "failed", ms(d["wall"][0]) if d else "–"]
            continue
        rs = d["rounds"]
        row += [ms(rs[0]), ms(min(rs[1:]) if len(rs) > 1 else rs[0]), ms(d["wall"][0])]
    print("| " + " | ".join(row) + " |")
print()
checks = []
for c in configs:
    # Stock HotSpot is not jailed: the three escapes succeed there.
    good = ok(c, "demo", "failures: 0" if c in ("hotspot", "hotspot-xint") else "failures: 3") and ok(c, "xml", "elements 20502") and ok(c, "cpu", "check ") and ok(c, "hello", "hello from")
    checks.append(f"{c}: {'outputs as expected' if good else 'UNEXPECTED OUTPUT, see raw'}")
cpu = {c: next((l for l in get(c, "cpu")["out"] if l.startswith("check ")), None) for c in configs if get(c, "cpu")}
print("Sanity: " + "; ".join(checks) + ".")
print(f"CpuBench checksums: {sorted(set(v for v in cpu.values() if v))} (one value means all configurations computed the same result).")
PY
cat results/bench.md
