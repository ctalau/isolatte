# oxygen-userguide-build

Compare building the Oxygen XML Editor PDF user guide with the DITA-OT working
tree and Java temporary files rooted in `/tmp` (tmpfs) versus a regular
filesystem directory.  The script measures wall-clock build time and the disk
space consumed by each run's output and intermediate artefacts.

## Workload

| Item | Value |
|------|-------|
| DITA-OT version | 4.3.1 |
| Source repo | `oxygenxml/userguide` (shallow clone) |
| DITA map | `DITA/UserManual.ditamap` |
| Ditaval filter | `DITA/ditaval/editor-sa.ditaval` |
| Output format | PDF (Apache FOP) |

## What is measured

* **Wall-clock build time** for each run (`time.perf_counter`).
* **Output directory size** (`du -sb` on the per-run output folder).
* **Java temp directory size** (`du -sb` on the per-run `java.io.tmpdir`);
  FOP writes ~300–600 MiB of intermediate files here.
* **Total disk consumed** — output + Java temp combined, reported in MiB.

## Runs

| Run | Output folder | `java.io.tmpdir` |
|-----|--------------|-----------------|
| 1 — tmpfs | `/tmp/oxygen-build-tmp/out` | `/tmp/oxygen-build-tmp/javatmp` |
| 2 — regular | `$HOME/oxygen-build-reg/out` | `$HOME/oxygen-build-reg/javatmp` |

Shared artefacts (DITA-OT zip, userguide clone) are downloaded once into
`$SHARED_DIR` (default `/tmp/oxygen-build-shared`) to keep download time out
of the measurements.

## Usage

```
bash measure_disk.sh
# Override shared cache location:
SHARED_DIR=/opt/dita-cache bash measure_disk.sh
```

## Prerequisites

Installed automatically when missing: `java` (`default-jre-headless`), `curl`,
`unzip`, `git`, `python3`.
