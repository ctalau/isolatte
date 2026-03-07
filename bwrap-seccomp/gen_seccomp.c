/*
 * gen_seccomp.c — emit a seccomp-BPF filter for the Node.js sandbox.
 *
 * Strategy: default ALLOW, then DENY a curated list of dangerous syscalls.
 * Network sockets are blocked by family (AF_INET/AF_INET6/AF_NETLINK/AF_PACKET)
 * as a substitute for --unshare-net (unavailable inside Docker).
 *
 * Build: gcc -O2 -o gen_seccomp gen_seccomp.c -lseccomp
 * Usage: ./gen_seccomp <output-file>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <seccomp.h>
#include <unistd.h>

static int deny(scmp_filter_ctx ctx, int syscall_nr) {
    return seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), syscall_nr, 0);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <output-file>\n", argv[0]);
        return 1;
    }

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) { perror("seccomp_init"); return 1; }

    /* ── Sandbox escape / kernel exploitation ─────────────────────────── */
    deny(ctx, SCMP_SYS(ptrace));               /* attach to any process    */
    deny(ctx, SCMP_SYS(process_vm_readv));     /* read other proc memory   */
    deny(ctx, SCMP_SYS(process_vm_writev));    /* write other proc memory  */
    deny(ctx, SCMP_SYS(perf_event_open));      /* CPU/cache side channels  */
    deny(ctx, SCMP_SYS(kcmp));                 /* process comparison leak  */
    deny(ctx, SCMP_SYS(userfaultfd));          /* often used in heap spray */

    /* ── Namespace / mount manipulation ──────────────────────────────── */
    deny(ctx, SCMP_SYS(unshare));              /* create new namespaces    */
    deny(ctx, SCMP_SYS(setns));                /* join host namespaces      */
    deny(ctx, SCMP_SYS(mount));                /* mount filesystems        */
    deny(ctx, SCMP_SYS(umount2));
    deny(ctx, SCMP_SYS(pivot_root));
    deny(ctx, SCMP_SYS(chroot));

    /* ── Device / firmware / hardware ───────────────────────────────── */
    deny(ctx, SCMP_SYS(mknod));
    deny(ctx, SCMP_SYS(mknodat));
    deny(ctx, SCMP_SYS(iopl));
    deny(ctx, SCMP_SYS(ioperm));
    deny(ctx, SCMP_SYS(kexec_load));
    deny(ctx, SCMP_SYS(kexec_file_load));
    deny(ctx, SCMP_SYS(reboot));

    /* ── Kernel key management ───────────────────────────────────────── */
    deny(ctx, SCMP_SYS(keyctl));
    deny(ctx, SCMP_SYS(add_key));
    deny(ctx, SCMP_SYS(request_key));

    /* ── BPF (can load arbitrary kernel code) ────────────────────────── */
    deny(ctx, SCMP_SYS(bpf));

    /* ── Bypass filesystem path restrictions ─────────────────────────── */
    deny(ctx, SCMP_SYS(open_by_handle_at));
    deny(ctx, SCMP_SYS(name_to_handle_at));

    /* ── System state manipulation ───────────────────────────────────── */
    deny(ctx, SCMP_SYS(syslog));
    deny(ctx, SCMP_SYS(acct));
    deny(ctx, SCMP_SYS(settimeofday));
    deny(ctx, SCMP_SYS(adjtimex));
    deny(ctx, SCMP_SYS(clock_adjtime));
    deny(ctx, SCMP_SYS(quotactl));
    deny(ctx, SCMP_SYS(fanotify_init));
    deny(ctx, SCMP_SYS(lookup_dcookie));
    deny(ctx, SCMP_SYS(nfsservctl));

    /* ── Network: block inet families (net-ns substitute) ────────────── *
     * AF_UNIX (1) sockets are kept: libuv uses them internally.         */
    int inet_families[] = {
        AF_INET,       /*  2 */
        AF_INET6,      /* 10 */
        AF_NETLINK,    /* 16 */
        AF_PACKET,     /* 17 */
        AF_VSOCK,      /* 40 */
    };
    for (int i = 0; i < (int)(sizeof(inet_families)/sizeof(inet_families[0])); i++) {
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socket), 1,
                         SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)inet_families[i]));
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(socketpair), 1,
                         SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)inet_families[i]));
    }

    /* ── Write filter to file ────────────────────────────────────────── */
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); seccomp_release(ctx); return 1; }

    int ret = seccomp_export_bpf(ctx, fd);
    if (ret < 0) {
        fprintf(stderr, "seccomp_export_bpf: %s\n", strerror(-ret));
        close(fd); seccomp_release(ctx); return 1;
    }
    close(fd);
    seccomp_release(ctx);
    return 0;
}
