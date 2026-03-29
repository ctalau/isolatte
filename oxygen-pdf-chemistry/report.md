# Oxygen PDF Chemistry + DITA-OT — Build Analysis

**Date:** 2026-03-28
**Source:** `oxygenxml/userguide` — 2,757 DITA topics
**Ditamap:** `DITA/UserManual.ditamap`
**Ditaval filter:** `DITA/ditaval/editor-sa.ditaval`
**Chemistry version:** 28.1 (build 2026-03-17)
**DITA-OT version:** 4.3.1 (Apache FOP renderer)
**Host:** Ubuntu 24.04.3 LTS · x86_64 · kernel 6.18.5 · OpenJDK 21.0.10

---

## 1  Full Pipeline — Setup + Build

| # | Step | Wall time | % | Notes |
|---|------|-----------|---|-------|
| 1 | `git clone --depth 1 oxygenxml/userguide` | **4.0 s** | 3% | 6,201 files, 2,757 DITA topics |
| 2 | `curl` — download `oxygen-pdf-chemistry.zip` | **1.5 s** | 1% | ~120 MB |
| 3 | `unzip` — extract Chemistry | **1.1 s** | 1% | |
| 4 | **Chemistry PDF build** (demo — 1 page, no license) | **3.0 s** | 2% | |
| 5 | `curl` — download `dita-ot-4.3.1.zip` | **1.2 s** | 1% | |
| 6 | `unzip` — extract DITA-OT | **0.5 s** | <1% | |
| 7 | **DITA-OT PDF build** (Apache FOP — full output) | **1m 37.6 s** | 92% | 3,104 pages |

**Total first-time wall time:** ~1m 52 s
**Repeat build time (step 7 only):** ~1m 38 s

---

## 2  DITA-OT Build — Phase Breakdown (step 7, 97.6 s total)

Phases detected from DITA-OT 4.x `==>` progress markers in the Ant log.

| Phase | Start | Duration | Peak RSS | Avg RSS |
|-------|-------|----------|----------|---------|
| JVM startup + project init | 0.0 s | 0.9 s | — | — |
| Merge DITAVAL files | 0.9 s | 0.1 s | — | — |
| Read input map files | 1.1 s | **0.9 s** | 173 MB | 173 MB |
| Resolve mapref in ditamap | 1.9 s | **1.3 s** | 251 MB | 222 MB |
| Resolve input map files keyref | 3.5 s | **0.8 s** | 302 MB | 275 MB |
| **Read topic files to temporary store** | 4.2 s | **11.5 s** | 364 MB | 352 MB |
| Resolve keyref | 15.9 s | **2.5 s** | 369 MB | 365 MB |
| **Resolve conref in input files** | 18.4 s | **6.1 s** | 596 MB | 486 MB |
| Normalize topic fragments / coderef | 24.5 s | **2.1 s** | 583 MB | 583 MB |
| **Move metadata entries** | 26.7 s | **5.5 s** | 726 MB | 619 MB |
| Pull metadata for links and xrefs | 32.4 s | **4.2 s** | 871 MB | 831 MB |
| **Merge topics** | 36.8 s | **7.2 s** | 1.35 GB | 1.14 GB |
| **Build FO** (DITA → XSL-FO) | 44.0 s | **24.6 s** | 2.16 GB | 1.36 GB |
| **Format PDF** (FOP rendering) | 68.6 s | **28.9 s** | 3.15 GB | 2.23 GB |
| Clean temp directory | 97.5 s | 0.1 s | — | — |

**The two rendering phases dominate: Build FO (25%) + Format PDF (30%) = 55% of total time.**

---

## 3  RAM Usage — DITA-OT Build

Sampled every 500 ms via `/proc/<pid>/status → VmRSS` (thread-group-leader only).

| Elapsed (s) | RSS | Phase |
|-------------|-----|-------|
| 1 | 84 MB | JVM init |
| 3 | 181 MB | Map reading |
| 5 | 334 MB | Map resolution |
| 9 | 352 MB | Topic reading |
| 15 | 364 MB | Topic reading |
| 21 | 466 MB | Conref resolution |
| 27 | 584 MB | Metadata |
| 33 | 730 MB | Metadata / link info |
| 37 | 874 MB | Merge topics |
| 41 | 1.21 GB | Merge topics |
| 45 | 1.50 GB | Build FO |
| 51 | 2.16 GB | Build FO |
| 55 | 1.74 GB | Build FO (GC) |
| 57 | 995 MB | Build FO (GC) |
| 67 | 1.06 GB | Format PDF |
| 72 | 1.42 GB | Format PDF |
| 78 | 1.93 GB | Format PDF |
| 88 | 2.56 GB | Format PDF |
| 94 | 2.94 GB | Format PDF |
| 97 | **3.15 GB** ← peak | Format PDF |

**Peak RSS: 3.15 GB** during Apache FOP PDF rendering.
A significant GC event occurs around 55 s (RAM drops from 2.16 GB → 995 MB) as FOP
finishes processing all topics and releases the XSL-FO tree before writing pages.

---

## 4  Chemistry Build (step 4, demo mode)

| Phase | Duration | Peak RSS |
|-------|----------|----------|
| JVM startup + init | 0.22 s | — |
| DITA map loading + topic resolution | 2.54 s | 228 MB |
| Rendering (1 page, stamped) + output | 0.20 s | 228 MB |

Chemistry v28.1 runs in **demo mode** without a license: it reads and resolves all
2,757 DITA topics (same preprocessing cost as DITA-OT) but stops after rendering
page 1 and writes an 8 KB stamped output.  Peak RSS is 228 MB — well under the
`-Xmx512m` heap cap.

---

## 5  Output Files

| Renderer | PDF size | Pages | Wall time | Peak RSS |
|----------|----------|-------|-----------|----------|
| Oxygen PDF Chemistry 28.1 (demo, unlicensed) | **8.1 KB** | 1 | 3.0 s | 228 MB |
| DITA-OT 4.3.1 / Apache FOP (full) | **25.9 MB** | **3,104** | 1m 37.6 s | 3.15 GB |

---

## 6  Key Observations

### Format PDF is the bottleneck
Apache FOP's page composition is the single most expensive phase: **28.9 s** and
**3.15 GB** peak RSS.  FOP holds the entire laid-out document in memory before
flushing pages to disk, which explains the monotone RSS growth followed by a GC
drop at ~55 s.

### Build FO is the second-largest phase
Transforming 2,757 DITA topics into a single XSL-FO file takes **24.6 s** and peaks
at **2.16 GB**.  The merged FO tree for a 3,104-page manual is substantial.

### Topic loading saturates at ~360 MB
Reading all 2,757 topics takes **11.5 s** and stabilises at **364 MB** RSS — roughly
132 KB per topic in-heap.  Subsequent resolution passes (conref, keyref, metadata)
add another ~500 MB before merging begins.

### DITA-OT RAM spike pattern
RAM grows in three distinct steps:
1. **Input processing** (0–36 s): 84 MB → 870 MB (topic tree, resolution graphs)
2. **Merge + FO build** (36–68 s): 870 MB → 2.16 GB (full FO tree in memory)
3. **FOP rendering** (68–98 s): GC reset to ~1 GB → peaks at **3.15 GB** (page buffers)

### Measurement note
Initial RAM sampling with `pstree` reported 9.78 GB (Java thread inflation).
Corrected sampler counts only thread-group leaders (`Tgid == Pid`), yielding
accurate figures above.
