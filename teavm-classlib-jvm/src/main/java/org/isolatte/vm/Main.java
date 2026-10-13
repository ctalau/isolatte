package org.isolatte.vm;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs a guest program: {@code Main [--jail DIR] --cp A:B:... MainClass args...}.
 *
 * <p>The guest class path should start with TeaVM's class library (teavm-classlib, teavm-core,
 * teavm-interop, ...). With {@code --jail}, the guest's VirtualFileSystem (the one TeaVM's java.io
 * and java.nio.file are written against) is {@code org.isolatte.guest.JailFileSystem}, whose only
 * host access is {@link Jail}: read-only, confined to DIR.
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        String jail = null;
        String cp = null;
        int i = 0;
        for (; i < args.length && args[i].startsWith("--"); i++) {
            switch (args[i]) {
                case "--jail" -> jail = args[++i];
                case "--cp" -> cp = args[++i];
                default -> throw new IllegalArgumentException(args[i]);
            }
        }
        String mainClass = args[i++].replace('.', '/');
        List<String> guestArgs = List.of(args).subList(i, args.length);
        Loader loader = new Loader();
        for (String e : cp.split(":")) {
            loader.add(Path.of(e));
        }
        PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true);
        PrintStream err = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err), true);
        VM vm = new VM(loader);
        Intrinsics.register(vm, out, err);
        List<java.io.File> jars = new ArrayList<>();
        for (String e : cp.split(":")) {
            jars.add(new java.io.File(e));
        }
        Metadata.register(vm, jars);
        if (jail != null) {
            new Jail(Path.of(jail)).register(vm);
        }
        int[] exit = {0};
        String jailDir = jail;
        Thread t = new Thread(null, () -> exit[0] = run(vm, jailDir, mainClass, guestArgs, err), "guest", 4L << 30);
        long start = System.nanoTime();
        t.start();
        t.join();
        if (System.getenv("VM_STATS") != null) {
            err.printf("[vm] %d guest classes, %d bytecodes, %d ms%n", vm.classes.size(), vm.instructions,
                    (System.nanoTime() - start) / 1_000_000);
            err.println("[vm] missing: " + vm.missing);
        }
        System.exit(exit[0]);
    }

    private static int run(VM vm, String jail, String mainClass, List<String> args, PrintStream err) {
        try {
            vm.boot();
            if (jail != null) {
                vm.callStatic("org/isolatte/guest/Boot", "init()V");
            }
            VClass main = vm.load(mainClass);
            vm.initialize(main);
            RefArray guestArgs = new RefArray(vm.arrayOf(vm.stringClass), args.size());
            for (int k = 0; k < args.size(); k++) {
                guestArgs.data[k] = vm.str(args.get(k));
            }
            VMethod m = main.methods.get("main([Ljava/lang/String;)V");
            vm.invoke(m, new Object[] {guestArgs});
            flush(vm);
            return 0;
        } catch (GuestException e) {
            flush(vm);
            err.println("[vm] uncaught guest exception: " + vm.describe(e.exception));
            try {
                vm.callVirtual("printStackTrace()V", e.exception);
                flush(vm);
            } catch (RuntimeException e2) {
                err.println("[vm] printStackTrace failed: " + e2);
            }
            return 1;
        }
    }

    private static void flush(VM vm) {
        try {
            vm.callVirtual("flush()V", vm.callStatic("java/lang/System", "out()Ljava/io/PrintStream;"));
            vm.callVirtual("flush()V", vm.callStatic("java/lang/System", "err()Ljava/io/PrintStream;"));
        } catch (RuntimeException e) {
            // best effort
        }
    }
}
