# Results — oxygen-userguide-build

Measured on 2026-03-08.  Host: Linux 6.18.5.

## Configuration

| Item | Value |
|------|-------|
| DITA-OT | 4.3.1 |
| Userguide repo | oxygenxml/userguide (shallow clone, HEAD) |
| Output format | PDF (Apache FOP) |
| JRE | default-jre-headless (OpenJDK) |
| Run 1 root | `/tmp/oxygen-build-tmp` (tmpfs) |
| Run 2 root | `$HOME/oxygen-build-reg` (ext4) |

Each run gets a **private copy of the unpacked DITA-OT tree** so that
DITA-OT's own plugin cache does not carry state between runs.  The userguide
source and the DITA-OT zip are shared and downloaded only once.

## Raw results

```
run                             time (s)   out (MiB)  java (MiB)  dita-ot (MiB)  total (MiB)
Run 1 — tmpfs (/tmp)           183.249        25.9         0.0          76.3       102.2
Run 2 — regular (/root)        161.617        25.9         0.0          76.3       102.2

Disk delta (regular - tmpfs) : +0.0 MiB
```

## Key findings

### Disk space — identical

Both runs consume **102.2 MiB** on their respective filesystems:

| Component | Size |
|-----------|------|
| PDF output (`out/`) | 25.9 MiB |
| DITA-OT tree copy (`dita-ot/`) | 76.3 MiB |
| Java temp dir (`javatmp/`) | 0.0 MiB |

The Java temp directory (`java.io.tmpdir`) is **empty after the build
completes**.  Apache FOP writes intermediate XSL-FO and area tree files there
during the run but cleans them up before the JVM exits, so no persistent disk
usage is attributable to that path.  There is no measurable disk-space
difference between building in `/tmp` and building on a regular filesystem.

> **Note**: Peak tmpfs memory pressure during the build was not instrumented.
> FOP's intermediate files can reach several hundred MiB at peak; they reside
> in RAM when `java.io.tmpdir` points to a tmpfs mount.  That peak usage was
> not captured here because `du` was measured only after the build finished.

### Build time — regular dir ~12 % faster

| Run | Time (s) |
|-----|---------|
| tmpfs (`/tmp`) | 183.2 |
| regular (ext4) | 161.6 |
| delta | −21.6 s (−12 %) |

The tmpfs run was **21.6 s slower** despite writing to RAM-backed storage.
This is consistent with tmpfs adding memory pressure: when `java.io.tmpdir`
is a tmpfs mount, FOP's large intermediate files compete for RAM with the JVM
heap, leading to increased GC pressure and/or page eviction.  On a host with
ample free RAM the gap would likely shrink or reverse.

## Conclusions

1. **Disk footprint is the same** (≈ 102 MiB) regardless of whether the build
   runs in `/tmp` or on a regular filesystem, because DITA-OT and FOP clean up
   their temporary artefacts on exit.

2. **Building on a regular filesystem was faster** in this run (+12 %).  Using
   `/tmp` for `java.io.tmpdir` does not provide a speed advantage when RAM is
   constrained; the tmpfs mount trades disk I/O for RAM pressure.

3. The dominant disk consumer is the **DITA-OT installation copy** (76.3 MiB),
   not the generated PDF (25.9 MiB).  Sharing a single read-only DITA-OT tree
   across concurrent builds (rather than copying it) would be the most
   effective way to reduce per-build disk usage.
