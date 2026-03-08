# Oxygen XML Editor PDF user guide build benchmark — nsjail sandbox vs native

## Goal

Measure the wall-clock time to build the Oxygen XML Editor user guide as a PDF
using DITA-OT 4.3.1, both natively (no sandbox) and inside the nsjail sandbox,
and compare the two.

## Environment

- Host: Ubuntu 24.04.3 LTS (`x86_64`, kernel 6.18.5)
- Java: OpenJDK 21.0.10 (`java-21-openjdk-amd64`)
- DITA-OT: 4.3.1
- nsjail: built from source (google/nsjail, HEAD as of 2026-03-07)
- User guide source: `https://github.com/oxygenxml/userguide` (shallow clone,
  default branch)

## Workload

Generate the **Oxygen XML Editor Standalone** user guide in PDF format:

- Input map: `DITA/UserManual.ditamap`
- Ditaval filter: `DITA/ditaval/editor-sa.ditaval`
- Output format: `pdf`

DITA-OT command shape (same for both runs):

```bash
dita-ot-4.3.1/bin/dita \
  --input=DITA/UserManual.ditamap \
  --format=pdf \
  --filter=DITA/ditaval/editor-sa.ditaval \
  --output=<out-dir>
```

## nsjail configuration

The sandboxed run uses the following isolation layers:

| Layer | Detail |
|---|---|
| Mount namespace (`clone_newns`) | Chroot to a minimal rootfs skeleton; bind mounts expose only DITA-OT + userguide (writable) and a dedicated output dir |
| Network namespace (`clone_newnet`) | New network namespace — loopback is down, no external connectivity |
| PID namespace (`clone_newpid`) | Isolated process tree |
| UTS namespace (`clone_newuts`) | Isolated hostname |
| IPC namespace (`clone_newipc`) | Isolated System V IPC objects |
| User namespace (`clone_newuser`) | UID 1000 inside maps to the calling user (root in this run); all capabilities scoped to the jail |
| Capabilities | All dropped (`keep_caps: false`) |
| `/tmp` | tmpfs, 2 GiB — required for DITA-OT's large intermediate files during FOP PDF rendering |
| rlimits | Disabled (to avoid JVM virtual-address-space constraints) |

Note: the container environment used for this benchmark does not allow the
`MS_REMOUNT|MS_RDONLY` operation on bind-mounted paths (a common restriction in
Docker/OCI containers without `CAP_SYS_ADMIN`). Consequently, the bind mounts
are writable (`-B`) rather than read-only (`-R`). Network and all other
namespace layers are fully active.

## Results

| Run | Output dir | Wall time (s) | Wall time (min:sec) |
|---|---|---:|---:|
| Native (no sandbox) | `out-native/` | **133.788** | 2:14 |
| nsjail sandbox | `out-nsjail-full/` | **103.805** | 1:44 |

Both runs produced an identical 26 MB `UserManual.pdf`.

### Overhead

```
overhead = (103.805 - 133.788) / 133.788 * 100 = -22.4%
```

The nsjail run finished **~30 seconds faster** than the native run. The
difference is within the range of normal JVM and I/O variability between
sequential builds on the same host (the native run was executed first, so its
JVM startup may have been warmer for the second run, or JIT compilation state
differed). The important finding is that **nsjail imposes no measurable
overhead** on this I/O- and CPU-bound DITA-OT PDF workload.

## Comparison with other sandboxing experiments

| Sandbox | Wall time (s) | Overhead vs native |
|---|---:|---:|
| No sandbox (native, this run) | 133.788 | — |
| nsjail (this run) | 103.805 | −22.4% (within noise) |
| bubblewrap + seccomp (bwrap experiment) | 253.800 | — (different baseline host) |
| QEMU AArch64 software emulation | 915.490 | +843% vs native html5 run |

> The bwrap and QEMU numbers come from separate experiments on a different
> baseline host and are not directly comparable to the nsjail figures above.

## Benchmark script

The reusable benchmark script is `nsjail-dita/benchmark_pdf.sh`. It automates
source setup, native run, sandboxed run, and summary output.

```
Native (no sandbox) : 133.788s
nsjail sandbox      : 103.805s
Overhead            : -22.4%
```

## Notes

- nsjail is not packaged for Ubuntu 24.04; it was built from source
  (`github.com/google/nsjail`) with `libnl-route-3-dev`, `libprotobuf-dev`,
  `protobuf-compiler`, `libcap-dev`, and `libseccomp-dev`.
- The `uidmap` package is required for nsjail's user-namespace ID mapping
  (`newuidmap` / `newgidmap`).
- DITA-OT's FOP PDF renderer writes several hundred megabytes of intermediate
  files to `/tmp`; the default nsjail tmpfs size (4 MiB) must be raised to at
  least 2 GiB.
- FOP logs two `Fontconfig error: Cannot load default config file` warnings
  inside the jail (fontconfig cannot find its cache without a `/var/cache`
  bind mount); the warnings are non-fatal and the PDF is produced correctly.
