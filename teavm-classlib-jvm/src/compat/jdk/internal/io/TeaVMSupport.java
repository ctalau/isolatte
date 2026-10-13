package jdk.internal.io;

/** Static methods that TeaVM adds to its own java.lang.System; calls are redirected here. */
public final class TeaVMSupport {
    private TeaVMSupport() {
    }

    public static String getTempDir() {
        return System.getProperty("java.io.tmpdir", "/tmp");
    }
}
