package org.mini.fs;

/**
 * Attack fixture for the sandbox probe: guest code impersonating miniJVM's own file class. miniJVM
 * binds natives by class and method name, so without the native allowlist this would open host
 * files. On HotSpot it is just an unbound native.
 */
public final class InnerFile {
    private InnerFile() {
    }

    public static native long openFile(byte[] filePath, byte[] mode);
}
