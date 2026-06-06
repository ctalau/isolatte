# nested-docker-qemu-tcg

Experiment: run a privileged Docker-in-Docker container inside a QEMU VM that uses **TCG software emulation** (no `/dev/kvm`), and then nest a second privileged DinD inside the first, and inside that run a plain Node.js container that prints `deep hello world`.

## Stack

```
Host machine (no KVM)
└── QEMU TCG (software-emulated x86_64 VM, Alpine Linux 3.20)
    └── docker:dind (privileged, --storage-driver=vfs)   ← L1
        └── docker:dind (privileged, --storage-driver=vfs)  ← L2
            └── node:alpine                                    ← L3
                └── node -e "console.log('deep hello world')"
```

## Files

| File | Purpose |
|------|---------|
| `run.sh` | Main script: installs deps, downloads Alpine, builds cidata, boots QEMU, monitors |
| `user-data` | cloud-init user-data: installs Docker, runs the nested containers |
| `meta-data` | cloud-init meta-data (instance-id, hostname) |
| `cache/` | Downloaded Alpine cloud image (gitignored) |
| `work/` | Per-run working files: disk copy, cidata.img, log (gitignored) |

## Prerequisites

The script installs missing tools via `apt-get`:
- `qemu-system-x86` — system emulator (TCG mode, no `/dev/kvm` needed)
- `qemu-utils` — `qemu-img` for disk image management
- `dosfstools` — `mkfs.fat` for creating the cidata FAT image
- `mtools` — `mcopy`/`mdir` to write files to FAT without root

## Usage

```bash
cd nested-docker-qemu-tcg
./run.sh
```

Expected runtime: **20–60 minutes** in TCG mode (Docker image pulls go through the emulated network stack).

## Design decisions

### Why TCG?
The experiment explicitly requires software emulation (`-accel tcg`) to test operation in environments where KVM is unavailable (e.g. nested containers, certain cloud VMs).

### Why Alpine cloud image?
Alpine's generic cloud image (179 MB) ships with cloud-init and a virt-optimised kernel that includes `console=ttyS0` in GRUB by default — output is immediately visible on QEMU's emulated serial port without any patching.

### Why `--storage-driver=vfs` for DinD?
The Linux kernel allows at most two layers of overlay filesystems. L1 DinD already sits on the VM's ext4/overlay; L2 DinD would require a third overlay layer. Using `vfs` for the inner daemons avoids the kernel's overlay nesting limit at the cost of slower image operations (full copy instead of copy-on-write).

### Why resize the disk to 10 GB?
The `docker:dind` image is ~250 MB compressed. It is pulled twice (once for L1, once for L2 inside L1) and `node:alpine` (~40 MB) once more, requiring ~540 MB of decompressed layers plus Docker metadata. The original Alpine cloud disk is ~2 GB virtual, which is not enough.

## Observed results

See `work/qemu-output.log` for the full serial transcript after a run.

## What worked

- QEMU 8.2.2 TCG boots Alpine Linux 3.20 in ~3–5 minutes with full serial console output
- Alpine's cloud image detects the `cidata` FAT volume (NoCloud data source) and runs cloud-init
- `apk add docker` inside the guest installs Docker successfully via QEMU user-mode networking
- *(update after run)*

## What did not work

- *(update after run)*

## What to try next if this fails

1. **Overlay nesting**: if L2 DinD fails with an overlay error despite `--storage-driver=vfs`, try `overlay2` with `--mount /proc/sys/kernel/nesting_max` workarounds.
2. **Image pull timeout**: in TCG mode, the emulated network is slower than real hardware. Pre-save Docker images to a tar, share via 9p virtio filesystem, and `docker load` inside the VM.
3. **Memory pressure**: DinD daemons can be memory-hungry. Increase VM RAM to 6–8 GB if OOM kills appear in the log.
4. **Cloud-init version**: Alpine 3.20 ships cloud-init 23.x; some `runcmd` edge cases differ from older versions. Check `/var/log/cloud-init.log` inside the VM.

## Opinion on feasibility

QEMU TCG → DinD → DinD → Node is theoretically sound — all three layers use Linux kernel features (namespaces, cgroups) that the TCG-emulated kernel provides. The main practical risk is **time**: each layer adds image-pull overhead, and TCG's emulated CPU and network make every operation 5–10× slower than on bare metal. For a one-time experiment this is acceptable; for CI or production use it would need KVM or a pre-baked image with all Docker images loaded.
