#!/usr/bin/env python3
"""Run Apache FOP with RSS sampling and optional JFR capture.

This script is intended for large-FO memory investigations where /usr/bin/time
is unavailable. It samples /proc/<pid>/status while FOP is running and reports:
- exit code
- elapsed wall clock
- peak RSS

Example:
  python3 fop_memory_profile.py \
    --cp-file /workspace/isolatte/.tmp/fop-src/fop/cp.txt \
    --prepend-jar /workspace/isolatte/.tmp/fop-src/fop-core/target/fop-core-2.11.0-SNAPSHOT.jar \
    --prepend-jar /workspace/isolatte/.tmp/fop-src/fop-util/target/fop-util-2.11.0-SNAPSHOT.jar \
    --prepend-jar /workspace/isolatte/.tmp/fop-src/fop-events/target/fop-events-2.11.0-SNAPSHOT.jar \
    --fo topic.fo --pdf /tmp/out.pdf --xmx 256m --relaxed --conserve \
    --log profiling/run.log --jfr profiling/run.jfr
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def read_peak_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        return 0
    return 0


def build_classpath(cp_file: Path, prepend_jars: list[str]) -> str:
    base = cp_file.read_text(encoding="utf-8").strip()
    parts = [p for p in prepend_jars if p] + [base]
    return ":".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp-file", required=True, type=Path)
    ap.add_argument("--prepend-jar", action="append", default=[])
    ap.add_argument("--fo", required=True, type=Path)
    ap.add_argument("--pdf", required=True, type=Path)
    ap.add_argument("--xmx", default="256m")
    ap.add_argument("--xms", default=None)
    ap.add_argument("--relaxed", action="store_true")
    ap.add_argument("--conserve", action="store_true")
    ap.add_argument("--log", required=True, type=Path)
    ap.add_argument("--jfr", type=Path)
    ap.add_argument("--heap-dump-path", type=Path)
    ap.add_argument("--print-class-histogram-on-oom", action="store_true")
    ap.add_argument("--capture-histo-rss-kb", type=int, default=0,
                    help="Capture jcmd GC.class_histogram once when RSS crosses this threshold (KB).")
    ap.add_argument("--histo-out", type=Path)
    ap.add_argument("--sample-ms", type=int, default=200)
    args = ap.parse_args()

    cp = build_classpath(args.cp_file, args.prepend_jar)
    cmd = ["java"]
    cmd += [f"-Xmx{args.xmx}"]
    if args.xms:
        cmd += [f"-Xms{args.xms}"]
    cmd += ["-Djava.awt.headless=true"]
    if args.jfr:
        cmd += [f"-XX:StartFlightRecording=filename={args.jfr},settings=profile,dumponexit=true"]
    if args.heap_dump_path:
        cmd += ["-XX:+HeapDumpOnOutOfMemoryError", f"-XX:HeapDumpPath={args.heap_dump_path}"]
    if args.print_class_histogram_on_oom:
        cmd += ["-XX:+PrintClassHistogram"]
    cmd += ["-cp", cp, "org.apache.fop.cli.Main"]
    if args.relaxed:
        cmd += ["-r"]
    if args.conserve:
        cmd += ["-conserve"]
    cmd += ["-fo", str(args.fo), "-pdf", str(args.pdf)]

    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.pdf.parent.mkdir(parents=True, exist_ok=True)
    if args.jfr:
        args.jfr.parent.mkdir(parents=True, exist_ok=True)
    if args.heap_dump_path:
        args.heap_dump_path.parent.mkdir(parents=True, exist_ok=True)
    if args.histo_out:
        args.histo_out.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    peak = 0
    histo_captured = False

    with args.log.open("w", encoding="utf-8") as log_f:
        proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT, text=True)
        while proc.poll() is None:
            rss_kb = read_peak_rss_kb(proc.pid)
            peak = max(peak, rss_kb)
            if (args.capture_histo_rss_kb and not histo_captured and rss_kb >= args.capture_histo_rss_kb):
                histo = subprocess.run(["jcmd", str(proc.pid), "GC.class_histogram"], capture_output=True, text=True)
                if args.histo_out:
                    args.histo_out.write_text(histo.stdout, encoding="utf-8")
                histo_captured = True
            time.sleep(args.sample_ms / 1000.0)
        rc = proc.wait()

    elapsed = time.perf_counter() - t0
    summary = {
        "exit_code": rc,
        "elapsed_s": round(elapsed, 3),
        "peak_rss_kb": peak,
        "peak_rss_mb": round(peak / 1024.0, 1),
        "log": str(args.log),
        "pdf": str(args.pdf),
        "jfr": str(args.jfr) if args.jfr else None,
        "heap_dump_path": str(args.heap_dump_path) if args.heap_dump_path else None,
        "histo_out": str(args.histo_out) if args.histo_out and histo_captured else None,
    }
    print(json.dumps(summary, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
