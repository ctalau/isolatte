package jdk.internal.io;

import java.io.IOException;

/**
 * The only way from this package to host files: libjava's existing JNI natives, implemented by the
 * package-private class java.io.HostFiles (registered SharedSecrets-style). The package is not
 * exported, so application code cannot reach it.
 */
public abstract class HostAccess {
    public static final int EXISTS = 0x01;
    public static final int REGULAR = 0x02;
    public static final int DIRECTORY = 0x04;

    private static HostAccess instance;

    protected static void register(HostAccess access) {
        instance = access;
    }

    static HostAccess get() {
        if (instance == null) {
            try {
                Class.forName("java.io.HostFiles", true, null);
            } catch (ClassNotFoundException e) {
                throw new InternalError(e);
            }
        }
        return instance;
    }

    /** {@code EXISTS}/{@code REGULAR}/{@code DIRECTORY} bits; follows symlinks. */
    public abstract int attributes(String hostPath);

    public abstract String[] list(String hostPath);

    public abstract long length(String hostPath);

    public abstract long lastModified(String hostPath);

    public abstract boolean canRead(String hostPath);

    /** realpath(3) of the longest existing prefix, rest normalized. */
    public abstract String canonicalize(String hostPath) throws IOException;

    public abstract VirtualFileAccessor openRead(String hostPath) throws IOException;
}
