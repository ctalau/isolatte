package org.isolatte.guest;

import java.net.URL;
import org.teavm.runtime.fs.VirtualFileSystemProvider;

/**
 * Entry point: {@code mini_jvm ... org.isolatte.guest.Boot MainClass args...}. Installs the jailed
 * VirtualFileSystem (TeaVM's java.io and java.nio.file are written against it) and a file: URL
 * handler, then runs {@code MainClass.main}.
 */
public final class Boot {
    private Boot() {
    }

    public static void init() {
        VirtualFileSystemProvider.setInstance(new JailFileSystem());
        URL.setURLStreamHandlerFactory(new FileURLHandler());
    }

    public static void main(String[] args) throws ClassNotFoundException {
        init();
        String[] rest = new String[args.length - 1];
        System.arraycopy(args, 1, rest, 0, rest.length);
        try {
            callMain(Class.forName(args[0]), rest);
        } finally {
            System.out.flush();
            System.err.flush();
        }
    }

    /** Runs {@code cls.main(args)}; implemented by the VM (no reflection metadata here). */
    private static native void callMain(Class<?> cls, String[] args);
}
