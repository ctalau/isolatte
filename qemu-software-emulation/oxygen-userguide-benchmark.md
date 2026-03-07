# Oxygen XML Editor User Guide build benchmark (native vs QEMU software emulation)

## Goal
Measure how long it takes to generate the Oxygen XML Editor user guide (`editor-sa`) with DITA-OT on:

1. Native `x86_64` Java runtime.
2. `AArch64` Java runtime executed via QEMU user-mode software emulation (`qemu-aarch64-static`).

## Environment
- Host architecture: `x86_64`
- Host Java: OpenJDK 21.0.2
- Emulated Java: Temurin JRE 21.0.10 (`aarch64`) run with `qemu-aarch64-static -L /usr/aarch64-linux-gnu`
- DITA-OT: 4.3.1
- User guide source: `https://github.com/oxygenxml/userguide` (default branch, shallow clone)

## Workload
Generate the **Oxygen XML Editor Standalone user guide** from:

- input map: `DITA/UserManual.ditamap`
- ditaval profile: `DITA/ditaval/editor-sa.ditaval`
- output format: `html5`

Command shape used in both runs:

```bash
/tmp/oxygen-exp/dita-ot-4.3.1/bin/dita \
  --input=DITA/UserManual.ditamap \
  --format=html5 \
  --filter=DITA/ditaval/editor-sa.ditaval \
  --output=<out-dir>
```

Timing method: Python `time.perf_counter()` around `subprocess.run(...)`.

## Results

| Run type | Output dir | Elapsed time (seconds) | Elapsed time (min:sec) |
|---|---|---:|---:|
| Native x86_64 Java | `out-native` | 97.103 | 1:37 |
| AArch64 Java via QEMU software emulation | `out-qemu` | 915.490 | 15:15 |

### Relative slowdown

- QEMU/user-mode emulation slowdown vs native: **~9.43x**

Computation:

```text
915.490 / 97.103 = 9.428...
```

## Notes
- Both builds completed and produced populated output folders.
- Both runs emitted non-fatal warnings about missing/remote resources while still finishing.
- Because this is user-mode software emulation, significant slowdown is expected for Java-heavy XML/XSLT pipelines.
