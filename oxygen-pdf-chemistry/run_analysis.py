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
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

# ── configuration ──────────────────────────────────────────────────────────────

USERGUIDE_REPO = "https://github.com/oxygenxml/userguide.git"
CHEMISTRY_URL  = "https://www.oxygenxml.com/InstData/Chemistry/oxygen-pdf-chemistry.zip"
DITA_VER       = "4.3.1"
DITA_OT_URL    = f"https://github.com/dita-ot/dita-ot/releases/download/{DITA_VER}/dita-ot-{DITA_VER}.zip"
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

    # ── DITA-OT 4.x progress markers: "==> Phase name" ────────────────────
    if stripped.startswith("==>"):
        name = stripped[3:].strip()
        if name:
            return name

    # ── Shell-script lines emitted before the JVM starts ──────────────────
    if stripped.startswith("Starting Chemistry"):
        return "Shell startup"
    if stripped.startswith("Java executable"):
        return "JVM launch"
    if stripped.startswith("Picked up JAVA_TOOL_OPTIONS"):
        return "JVM init (TOOL_OPTIONS)"

    # ── Chemistry structured log: "LEVEL  LoggerClass - Message" ──────────
    m = _CHEM_LOG_RE.match(stripped)
    if m:
        logger = m.group(2)
        if logger in _LOGGER_PHASE:
            return _LOGGER_PHASE[logger]
        for prefix, phase in _LOGGER_PHASE.items():
            if logger.startswith(prefix):
                return phase
        return logger

    # ── Generic Ant target / DITA-OT keyword fallback ─────────────────────
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

def _phases_section(step: StepResult, heading: str, min_dur_ms: float = 500) -> list[str]:
    """Return markdown rows for per-phase breakdown of a build step."""
    phases = extract_phases(step)
    nontrivial = [p for p in phases if (p["end_ms"] - p["start_ms"]) >= min_dur_ms]
    if not nontrivial:
        return []
    rows = [
        f"### {heading} Sub-Phases (≥ {min_dur_ms/1000:.1f} s)",
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
    return rows


def _ram_section(step: StepResult, heading: str) -> list[str]:
    """Return markdown rows for RAM-over-time of a build step."""
    if not step.ram_samples:
        return []
    rows = [
        f"### {heading} — RAM Over Time",
        "",
        "| Elapsed (s) | RSS |",
        "|-------------|-----|",
    ]
    stride = max(1, len(step.ram_samples) // 40)
    for t, rss in step.ram_samples[::stride]:
        elapsed = (t - step.start_ms) / 1000.0
        rows.append(f"| {elapsed:.0f} | {fmt_ram(rss)} |")
    rows.append("")
    return rows


def write_report(
    steps: list[StepResult],
    outputs: dict[str, Path],   # label → PDF path
    report_path: Path,
    topic_count: int,
) -> str:
    total_s      = sum(s.duration_s for s in steps)
    overall_peak = max((s.peak_rss_kb for s in steps), default=0)

    rows: list[str] = [
        "# Oxygen PDF Chemistry + DITA-OT — Build Analysis",
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

    # Per-build-step detail sections
    rows += ["## Build Step Details", ""]
    for s in steps:
        if not s.log_lines:
            continue
        rows += _phases_section(s, s.name)
        rows += _ram_section(s, s.name)

    # Output files
    rows += ["## Output Files", ""]
    for label, path in outputs.items():
        if path.exists():
            size_mb = path.stat().st_size / (1024 * 1024)
            rows.append(f"- **{label}:** `{path}` ({size_mb:.1f} MB)")
        else:
            rows.append(f"- **{label}:** not generated")
    rows.append("")

    # Aggregate warnings/errors from all steps with log lines
    for s in steps:
        problems = [
            (ts, l)
            for ts, l in s.log_lines
            if any(k in l for k in ("ERROR", "WARN", "Exception", "Error:"))
        ]
        if problems:
            rows += [f"## Warnings / Errors — {s.name}", ""]
            for ts, l in problems[:30]:
                elapsed = (ts - s.start_ms) / 1000.0
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
        "Chemistry PDF build (demo — 1 page, no license)",
        chem_cmd,
        env=chem_env,
        log_file=logs_dir / "chemistry.log",
        sample_ram=True,
    )
    steps.append(chem_step)

    # ── 4. Download DITA-OT ──────────────────────────────────────────────────
    dita_ot_zip = workdir / f"dita-ot-{DITA_VER}.zip"
    dita_ot_dir = workdir / f"dita-ot-{DITA_VER}"
    dita_bin    = dita_ot_dir / "bin" / "dita"

    if not dita_ot_dir.exists():
        if not dita_ot_zip.exists():
            step = run_step(
                f"Download DITA-OT {DITA_VER}",
                ["curl", "-fsSL", "-o", str(dita_ot_zip), DITA_OT_URL],
                log_file=logs_dir / "dita-ot-download.log",
                sample_ram=False,
            )
            if step.returncode != 0:
                log("ERROR: DITA-OT download failed")
                return 1
            steps.append(step)

        log(f"Extracting dita-ot-{DITA_VER}.zip …")
        t_start = ts_ms()
        with zipfile.ZipFile(dita_ot_zip) as zf:
            zf.extractall(workdir)
        ex = StepResult(f"Extract DITA-OT {DITA_VER}", t_start)
        ex.end_ms = ts_ms()
        steps.append(ex)
        log(f"DITA-OT extraction done in {fmt_dur(ex.duration_s)}")
    else:
        log(f"DITA-OT {DITA_VER} already present — skipping download")

    dita_bin.chmod(dita_bin.stat().st_mode | 0o755)
    log(f"DITA-OT binary: {dita_bin}")

    # ── 5. Run DITA-OT PDF build (Apache FOP — full output, free) ───────────
    java_exe = shutil.which("java") or "java"
    java_home = str(Path(java_exe).resolve().parent.parent)

    dita_output = workdir / "output-dita-ot"
    dita_output.mkdir(exist_ok=True)

    dita_env = os.environ.copy()
    dita_env["JAVA_HOME"] = java_home
    dita_env.setdefault("HOME", "/tmp")
    dita_env.setdefault("LANG", "C.UTF-8")
    dita_env.setdefault("LC_ALL", "C.UTF-8")

    dita_cmd = [
        str(dita_bin),
        f"--input={ditamap}",
        "--format=pdf",
        f"--filter={ditaval}",
        f"--output={dita_output}",
        "-v",   # verbose: emit Ant target names for phase detection
    ]

    dita_step = run_step(
        "DITA-OT PDF build (Apache FOP — full output)",
        dita_cmd,
        env=dita_env,
        log_file=logs_dir / "dita-ot.log",
        sample_ram=True,
    )
    steps.append(dita_step)

    # ── Report ───────────────────────────────────────────────────────────────
    dita_pdf = next(dita_output.glob("**/*.pdf"), None) or dita_output / "UserManual.pdf"
    outputs = {
        "Chemistry PDF (demo, 1 page)": output_pdf,
        "DITA-OT PDF (Apache FOP, full)": dita_pdf,
    }
    report = write_report(steps, outputs, report_path, topic_count)

    print("\n" + "=" * 70)
    print(report[:5000])
    if len(report) > 5000:
        print(f"\n… (full report at {report_path})")

    if dita_pdf.exists():
        log(f"SUCCESS — DITA-OT PDF: {dita_pdf} ({dita_pdf.stat().st_size / 1e6:.1f} MB)")
    else:
        log("WARNING — DITA-OT PDF not found")

    return 0 if dita_step.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
