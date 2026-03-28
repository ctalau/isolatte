# Oxygen PDF Chemistry — Build Analysis

**Date:** 2026-03-28
**Source:** `oxygenxml/userguide` — 2,757 DITA topics
**Ditamap:** `DITA/UserManual.ditamap`
**Ditaval filter:** `DITA/ditaval/editor-sa.ditaval`
**Chemistry version:** 28.1 (build 2026-03-17)
**JVM max heap:** `-Xmx512m`
**Host:** Ubuntu 24.04.3 LTS · x86_64 · kernel 6.18.5 · OpenJDK 21.0.10

> **Demo mode:** No license key was found.  Chemistry generated a single
> stamped/watermarked page and exited.  The full oxygenxml/userguide
> (approximately 1,000+ pages) requires a valid Oxygen PDF Chemistry license
> to produce complete output.  All timing figures below reflect real
> processing — Chemistry reads and resolves all 2,757 topics even in demo mode.

---

## 1  Full Pipeline — Setup + Build

| # | Step | Wall time | Notes |
|---|------|-----------|-------|
| 1 | `git clone --depth 1 oxygenxml/userguide` | **4.0 s** | 6,201 files checked out |
| 2 | `curl` — download `oxygen-pdf-chemistry.zip` | **1.5 s** | ~120 MB zip |
| 3 | `unzip` — extract Chemistry | **1.1 s** | |
| 4 | Chemistry PDF build — **run 1** (cold, no font cache) | **6.6 s** | includes font loading |
| — | Chemistry PDF build — **run 2** (warm font cache) | **3.0 s** | font cache populated |

**Total first-time wall time (steps 1–4):** ~13.2 s
**Repeat build wall time (step 4 only, warm cache):** ~3.0 s

---

## 2  Chemistry Build — Phase Breakdown

### Run 1 — Cold Start (6.6 s total)

Reconstructed from the timestamped log (`logs/chemistry.log`).

| Phase | Start | Duration | Notes |
|-------|-------|----------|-------|
| Shell startup + JVM launch | 0.00 s | **0.47 s** | `chemistry.sh` resolves paths, locates `java` |
| Chemistry init (version, license, max-memory) | 0.47 s | **0.01 s** | |
| Font cache miss | 0.48 s | **< 0.01 s** | `/root/.chemistry-cache` was a directory — cache discarded |
| Font loading (`OpenFont`, `AFMParser`) | 0.48 s | **4.64 s** | 7 TrueType collections; AFM type-1 fonts scanned; 4 warnings |
| DITA map loading + topic resolution | 5.12 s | **1.37 s** | 2,757 topics read; ditaval filter applied |
| Rendering (1 page, demo/stamped) + output | 6.49 s | **0.11 s** | |

**Font loading dominates cold-start time (70% of 6.6 s).**

### Run 2 — Warm Cache (3.0 s total)

| Phase | Start | Duration | Notes |
|-------|-------|----------|-------|
| Shell startup + JVM launch | 0.00 s | **0.22 s** | JVM class data shared from run 1 |
| Chemistry init | 0.22 s | **0.004 s** | |
| DITA map loading + topic resolution | 0.22 s | **2.54 s** | all 2,757 topics; ditaval filter |
| Rendering (1 page) + output | 2.76 s | **0.20 s** | |

**With fonts cached, DITA topic loading is 85% of total Chemistry time.**

---

## 3  RAM Usage (Chemistry JVM)

Sampled every 500 ms via `/proc/<pid>/status → VmRSS` (thread-group-leader
only to avoid double-counting Java threads).

| Elapsed | RSS |
|---------|-----|
| 0.2 s | 98 MB |
| 0.7 s | 143 MB |
| 1.2 s | 169 MB |
| 1.7 s | 202 MB |
| 2.3 s | **228 MB** ← peak |

**Peak RSS: 228 MB** (JVM heap -Xmx512m; actual usage well under the cap).
RAM grows monotonically throughout the build as topics and CSS are loaded into
the Java heap.

---

## 4  Output

| Item | Value |
|------|-------|
| PDF path | `/tmp/oxygen-chemistry-pdf/output/UserManual.pdf` |
| PDF size | **8.1 KB** (1 stamped demo page) |
| Pages rendered | 1 of ~1,000+ (demo-mode limit) |

---

## 5  Notable Observations

### Font cache issue (run 1)
`/root/.chemistry-cache` existed as a **directory** from a previous run,
causing Chemistry to discard the font cache and re-scan all system fonts on
cold start.  This added ~4.6 s.  Removing or correctly initialising the cache
path before first run eliminates this penalty.

### Measurement artefact — thread inflation
An initial RAM measurement using `pstree -p` and summing all listed PIDs
produced a spurious **9.78 GB** figure.  In Linux, each Java thread has its
own `/proc/<tid>/status` entry with the same `VmRSS` as the thread-group
leader; pstree's output includes thread IDs alongside process IDs, causing
N-fold inflation where N is the thread count (~40 threads for the Chemistry
JVM).  The corrected sampler reads only PIDs where `Tgid == Pid`, yielding the
accurate 228 MB figure.

### DITA processing with demo license
Even without a valid license Chemistry still **reads and resolves the full
2,757-topic tree** before stopping at page 1.  The 2.5 s topic-loading time
on warm runs is therefore representative of real production workloads up to
the rendering stage.
