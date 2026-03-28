#!/usr/bin/env python3
"""
Oxygen PDF Chemistry build pipeline analyzer.

Downloads DITA sources (oxygenxml/userguide), downloads Oxygen PDF Chemistry,
builds a PDF from DITA/UserManual.ditamap, and measures per-step timing and
RSS (resident set size) for each build phase.

Usage:
    python3 run_analysis.py [--workdir /tmp/oxygen-chemistry-pdf]
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

# ── configuration ──────────────────────────────────────────────────────────────

USERGUIDE_REPO = "https://github.com/oxygenxml/userguide.git"
CHEMISTRY_URL  = "https://www.oxygenxml.com/InstData/Chemistry/oxygen-pdf-chemistry.zip"
DITAMAP_REL    = "DITA/UserManual.ditamap"
DITAVAL_REL    = "DITA/ditaval/editor-sa.ditaval"

# ── helpers ────────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[analyzer] {msg}", flush=True)

def ts_ms() -> float:
    return time.time() * 1000

def fmt_dur(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m = int(seconds // 60)
    s = seconds % 60
    return f"{m}m {s:.1f}s"

def fmt_ram(kb: int) -> str:
    if kb == 0:
        return "—"
    if kb < 1024:
        return f"{kb} KB"
    if kb < 1024 * 1024:
        return f"{kb / 1024:.0f} MB"
    return f"{kb / 1024 / 1024:.2f} GB"

def get_tree_rss_kb(root_pid: int) -> int:
    """
    Return total RSS (KB) for the process tree rooted at root_pid.

    Uses /proc/<pid>/status to read VmRSS, but only counts PIDs where
    Pid == Tgid (i.e. the thread-group leader) to avoid summing the same
    address space once per Java thread.  Child processes are discovered
    iteratively via `ps --ppid`.
    """
    visited: set[int] = set()
    queue: list[int] = [root_pid]
    total = 0

    while queue:
        pid = queue.pop(0)
        if pid in visited:
            continue
        visited.add(pid)

        # Count RSS only for process leaders, not for threads
        try:
            pid_val = tgid_val = rss_val = None
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Pid:"):
                        pid_val = int(line.split()[1])
                    elif line.startswith("Tgid:"):
                        tgid_val = int(line.split()[1])
                    elif line.startswith("VmRSS:"):
                        rss_val = int(line.split()[1])
                    if None not in (pid_val, tgid_val, rss_val):
                        break
            if pid_val is not None and pid_val == tgid_val and rss_val:
                total += rss_val
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass

        # Discover direct children
        try:
            r = subprocess.run(
                ["ps", "--ppid", str(pid), "-o", "pid="],
                capture_output=True, text=True, timeout=1,
            )
            for tok in r.stdout.split():
                child = int(tok)
                if child not in visited:
                    queue.append(child)
        except Exception:
            pass

    return total

# ── phase detection ────────────────────────────────────────────────────────────

# Chemistry log format: "LEVEL  LoggerClass - Message"
_CHEM_LOG_RE = re.compile(r"^(INFO|WARN|ERROR)\s+([\w\$\.]+)\s+-\s+(.*)$")

# Map Chemistry logger class → human-readable phase name.
# Consecutive lines with the same phase name are grouped together.
_LOGGER_PHASE: dict[str, str] = {
    "OxygenPDFChemistry":         "OxygenPDFChemistry (init/finish)",
    "FontCache":                  "Font cache",
    "OpenFont":                   "Font loading (OpenFont)",
    "AFMParser$NotImplementedYet": "Font loading (AFM warnings)",
    "LoggingEventListener":       "Page rendering",
    "c":                          "License check",
}

# Generic Ant-style / DITA-OT patterns as fallback
_GENERIC_RE = [
    re.compile(r"^([\w][\w\-\.]+):\s*$"),   # Ant target "foo-bar:"
    re.compile(r"^\[(?:INFO|DITA-OT)\]\s+([\w][\w ,\-/\(\)]+?)(?:\.\.\.|\s*$)"),
]

def detect_phase(line: str) -> str | None:
    stripped = line.strip()

    # Shell-script header lines emitted before the JVM starts
    if stripped.startswith("Starting Chemistry"):
        return "Shell startup"
    if stripped.startswith("Java executable"):
        return "JVM launch"
    if stripped.startswith("Picked up JAVA_TOOL_OPTIONS"):
        return "JVM init (TOOL_OPTIONS)"

    # Chemistry structured log
    m = _CHEM_LOG_RE.match(stripped)
    if m:
        logger = m.group(2)
        # Exact match
        if logger in _LOGGER_PHASE:
            return _LOGGER_PHASE[logger]
        # Prefix match (e.g. "AFMParser$SomethingElse")
        for prefix, phase in _LOGGER_PHASE.items():
            if logger.startswith(prefix):
                return phase
        # Unknown logger: use it as the phase name
        return logger

    # Generic Ant / DITA-OT fallback
    for pat in _GENERIC_RE:
        gm = pat.match(stripped)
        if gm:
            name = gm.group(1).strip().rstrip(":")
            if len(name) >= 4:
                return name

    return None

# ── step result ────────────────────────────────────────────────────────────────

class StepResult:
    def __init__(self, name: str, start_ms: float):
        self.name       = name
        self.start_ms   = start_ms
        self.end_ms     = 0.0
        self.returncode = 0
        self.ram_samples: list[tuple[float, int]] = []  # (time_ms, rss_kb)
        self.log_lines:  list[tuple[float, str]]  = []  # (time_ms, text)
        self.peak_rss_kb  = 0
        self.avg_rss_kb   = 0.0

    def finalize(self):
        self.end_ms = ts_ms()
        if self.ram_samples:
            vals = [r for _, r in self.ram_samples]
            self.peak_rss_kb = max(vals)
            self.avg_rss_kb  = sum(vals) / len(vals)

    @property
    def duration_s(self) -> float:
        return (self.end_ms - self.start_ms) / 1000.0

# ── subprocess runner with instrumentation ─────────────────────────────────────

def run_step(
    name: str,
    cmd: list[str],
    *,
    env: dict | None = None,
    cwd: str | None = None,
    log_file: Path | None = None,
    sample_ram: bool = True,
) -> StepResult:
    """Run a subprocess, capture timestamped output, and sample RSS."""
    log(f"=== {name} ===")
    log(f"cmd: {' '.join(cmd)}")
    result   = StepResult(name, ts_ms())
    stop_ev  = threading.Event()
    proc_ref: list = [None]

    def _sampler():
        while not stop_ev.wait(0.5):
            p = proc_ref[0]
            if p is not None:
                rss = get_tree_rss_kb(p.pid)
                if rss > 0:
                    result.ram_samples.append((ts_ms(), rss))

    if sample_ram:
        sampler = threading.Thread(target=_sampler, daemon=True)
        sampler.start()

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    lf = open(log_file, "w") if log_file else None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=run_env,
            cwd=cwd,
        )
        proc_ref[0] = proc

        for line in proc.stdout:
            t = ts_ms()
            stripped = line.rstrip("\n")
            result.log_lines.append((t, stripped))
            if lf:
                lf.write(f"{t:.3f}\t{line}")
                lf.flush()
            print(line, end="", flush=True)

        proc.wait()
        result.returncode = proc.returncode
    finally:
        if lf:
            lf.close()
        stop_ev.set()
        if sample_ram:
            sampler.join(timeout=3)

    result.finalize()

    # Persist RAM samples next to the log for post-mortem analysis
    if log_file and result.ram_samples:
        ram_path = log_file.with_suffix(".ram.tsv")
        with open(ram_path, "w") as rf:
            rf.write("time_ms\trss_kb\n")
            for t, rss in result.ram_samples:
                rf.write(f"{t:.3f}\t{rss}\n")
    log(
        f"{name} done — {fmt_dur(result.duration_s)}, "
        f"exit={result.returncode}, peak_rss={fmt_ram(result.peak_rss_kb)}"
    )
    return result

# ── sub-phase extraction ───────────────────────────────────────────────────────

def extract_phases(step: StepResult) -> list[dict]:
    """
    Split a step's log lines into phases by detecting Ant targets /
    progress markers.  Returns a list sorted by start time.
    """
    phases: list[dict] = []
    cur_name  = "startup"
    cur_start = step.start_ms

    def close_phase(end_ms: float) -> None:
        rams = [r for t, r in step.ram_samples if cur_start <= t <= end_ms]
        phases.append({
            "name":       cur_name,
            "start_ms":   cur_start,
            "end_ms":     end_ms,
            "peak_rss_kb": max(rams) if rams else step.peak_rss_kb,
            "avg_rss_kb":  sum(rams) / len(rams) if rams else step.avg_rss_kb,
        })

    for ts, line in step.log_lines:
        pname = detect_phase(line)
        if pname and pname != cur_name:
            close_phase(ts)
            cur_name  = pname
            cur_start = ts

    close_phase(step.end_ms)
    return phases

# ── report ─────────────────────────────────────────────────────────────────────

def write_report(
    steps: list[StepResult],
    output_pdf: Path,
    report_path: Path,
    topic_count: int,
) -> str:
    total_s      = sum(s.duration_s for s in steps)
    overall_peak = max((s.peak_rss_kb for s in steps), default=0)

    rows: list[str] = [
        "# Oxygen PDF Chemistry — Build Analysis",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Source:** `oxygenxml/userguide` ({topic_count} DITA topics)  ",
        f"**Ditamap:** `{DITAMAP_REL}`  ",
        f"**Ditaval filter:** `{DITAVAL_REL}`  ",
        f"**Total wall time:** {fmt_dur(total_s)}  ",
        f"**Peak RSS (all steps):** {fmt_ram(overall_peak)}  ",
        "",
        "---",
        "",
        "## Pipeline Steps",
        "",
        "| # | Step | Duration | % Total | Peak RSS |",
        "|---|------|----------|---------|----------|",
    ]
    for i, s in enumerate(steps, 1):
        pct = s.duration_s / total_s * 100 if total_s > 0 else 0
        rows.append(
            f"| {i} | {s.name} | {fmt_dur(s.duration_s)} "
            f"| {pct:.1f}% | {fmt_ram(s.peak_rss_kb)} |"
        )
    rows.append("")

    # Chemistry sub-phases
    chem = next(
        (s for s in steps if "chemistry" in s.name.lower() or "Chemistry" in s.name),
        None,
    )
    if chem and chem.log_lines:
        phases = extract_phases(chem)
        nontrivial = [p for p in phases if (p["end_ms"] - p["start_ms"]) >= 500]
        if nontrivial:
            rows += [
                "## Chemistry Sub-Phases (≥ 0.5 s)",
                "",
                "| Phase | Duration | Peak RSS | Avg RSS |",
                "|-------|----------|----------|---------|",
            ]
            for p in nontrivial:
                dur = (p["end_ms"] - p["start_ms"]) / 1000.0
                rows.append(
                    f"| `{p['name'][:65]}` | {fmt_dur(dur)} "
                    f"| {fmt_ram(p['peak_rss_kb'])} | {fmt_ram(int(p['avg_rss_kb']))} |"
                )
            rows.append("")

    # RAM over time
    if chem and chem.ram_samples:
        rows += [
            "## RAM Over Time (Chemistry Step)",
            "",
            "| Elapsed (s) | RSS |",
            "|-------------|-----|",
        ]
        stride = max(1, len(chem.ram_samples) // 40)
        for t, rss in chem.ram_samples[::stride]:
            elapsed = (t - chem.start_ms) / 1000.0
            rows.append(f"| {elapsed:.0f} | {fmt_ram(rss)} |")
        rows.append("")

    # Output info
    if output_pdf.exists():
        size_mb = output_pdf.stat().st_size / (1024 * 1024)
        rows += [
            "## Output",
            "",
            f"- **PDF:** `{output_pdf}` ({size_mb:.1f} MB)",
            "",
        ]
    else:
        rows += [
            "## Output",
            "",
            "- PDF was **not generated** — Chemistry may require a license or failed.",
            "",
        ]

    # Warnings / errors
    if chem:
        problems = [
            (ts, l)
            for ts, l in chem.log_lines
            if any(k in l for k in ("ERROR", "WARN", "Exception", "Error:"))
        ]
        if problems:
            rows += ["## Warnings / Errors", ""]
            for ts, l in problems[:40]:
                elapsed = (ts - chem.start_ms) / 1000.0
                rows.append(f"- `[{elapsed:.0f}s]` {l.strip()}")
            rows.append("")

    content = "\n".join(rows)
    report_path.write_text(content)
    log(f"Report written → {report_path}")
    return content

# ── main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Oxygen PDF Chemistry build analyzer")
    parser.add_argument(
        "--workdir", default="/tmp/oxygen-chemistry-pdf",
        help="Working directory for downloads and build artefacts",
    )
    args = parser.parse_args()

    workdir       = Path(args.workdir)
    userguide_dir = workdir / "userguide"
    chemistry_zip = workdir / "oxygen-pdf-chemistry.zip"
    chemistry_dir = workdir / "oxygen-pdf-chemistry"
    output_pdf    = workdir / "output" / "UserManual.pdf"
    logs_dir      = workdir / "logs"
    script_dir    = Path(__file__).parent
    report_path   = script_dir / "report.md"

    for d in (workdir, logs_dir, output_pdf.parent):
        d.mkdir(parents=True, exist_ok=True)

    steps: list[StepResult] = []

    # ── 1. Clone oxygenxml/userguide ────────────────────────────────────────
    if not userguide_dir.exists():
        step = run_step(
            "Clone oxygenxml/userguide",
            ["git", "clone", "--depth", "1", USERGUIDE_REPO, str(userguide_dir)],
            log_file=logs_dir / "clone.log",
            sample_ram=False,
        )
        if step.returncode != 0:
            log("ERROR: git clone failed")
            return 1
        steps.append(step)
    else:
        log("userguide already present — skipping clone")

    topic_count = len(list((userguide_dir / "DITA").rglob("*.dita")))
    log(f"DITA topics: {topic_count}")

    ditamap = userguide_dir / DITAMAP_REL
    ditaval = userguide_dir / DITAVAL_REL
    if not ditamap.exists():
        log(f"ERROR: ditamap not found: {ditamap}")
        return 1

    # ── 2. Download Oxygen PDF Chemistry ────────────────────────────────────
    if not chemistry_dir.exists():
        if not chemistry_zip.exists():
            step = run_step(
                "Download Oxygen PDF Chemistry",
                ["curl", "-fsSL", "-o", str(chemistry_zip), CHEMISTRY_URL],
                log_file=logs_dir / "download.log",
                sample_ram=False,
            )
            if step.returncode != 0:
                log("ERROR: download failed")
                return 1
            steps.append(step)

        # Extract zip
        log("Extracting oxygen-pdf-chemistry.zip …")
        t_start = ts_ms()
        with zipfile.ZipFile(chemistry_zip) as zf:
            zf.extractall(workdir)
        # Locate extracted folder (may be named "oxygen-pdf-chemistry-28.1" etc.)
        candidates = sorted(
            p for p in workdir.iterdir()
            if p.is_dir() and "chemistry" in p.name.lower() and p != chemistry_dir
        )
        if candidates and not chemistry_dir.exists():
            candidates[0].rename(chemistry_dir)
        elapsed_s = (ts_ms() - t_start) / 1000
        log(f"Extraction done in {fmt_dur(elapsed_s)}")

        # Record as a step (no subprocess, so build manually)
        dl_result = StepResult("Extract Oxygen PDF Chemistry", t_start)
        dl_result.end_ms = ts_ms()
        steps.append(dl_result)
    else:
        log("Oxygen PDF Chemistry already present — skipping download")

    # Find chemistry.sh
    chemistry_sh = next(chemistry_dir.rglob("chemistry.sh"), None)
    if chemistry_sh is None:
        log(f"ERROR: chemistry.sh not found under {chemistry_dir}")
        log("Directory layout:")
        for p in sorted(chemistry_dir.rglob("*"))[:40]:
            log(f"  {p.relative_to(chemistry_dir)}")
        return 1
    chemistry_sh.chmod(chemistry_sh.stat().st_mode | 0o755)
    log(f"Chemistry executable: {chemistry_sh}")

    # ── 3. Run Chemistry PDF build ───────────────────────────────────────────
    # Chemistry bundles its own JVM; forward proxy + locale settings only.
    chem_env = {k: v for k, v in os.environ.items()
                if k in ("PATH", "HOME", "LANG", "LC_ALL",
                         "JAVA_TOOL_OPTIONS", "JAVA_HOME")}
    chem_env.setdefault("HOME", "/tmp")
    chem_env.setdefault("LANG", "C.UTF-8")
    chem_env.setdefault("LC_ALL", "C.UTF-8")

    chem_cmd = [
        str(chemistry_sh),
        "-in",  str(ditamap),
        "-out", str(output_pdf),
    ]
    if ditaval.exists():
        chem_cmd += ["-filter", str(ditaval)]

    chem_step = run_step(
        "Chemistry PDF build",
        chem_cmd,
        env=chem_env,
        log_file=logs_dir / "chemistry.log",
        sample_ram=True,
    )
    steps.append(chem_step)

    # ── Report ───────────────────────────────────────────────────────────────
    report = write_report(steps, output_pdf, report_path, topic_count)

    print("\n" + "=" * 70)
    print(report[:4000])
    if len(report) > 4000:
        print(f"\n… (full report at {report_path})")

    if output_pdf.exists():
        log(f"SUCCESS — PDF: {output_pdf} ({output_pdf.stat().st_size / 1e6:.1f} MB)")
    else:
        log("NOTE — PDF not generated; Chemistry may require a license for full output")

    return 0 if chem_step.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
