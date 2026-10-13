package org.isolatte.guest;

/**
 * Host file access for the guest, implemented by the VM ({@code org.isolatte.vm.Jail}). Paths are
 * virtual: the VM confines them to the jail folder.
 */
final class Jail {
    static final int EXISTS = 1;
    static final int REGULAR = 2;
    static final int DIRECTORY = 4;

    private Jail() {
    }

    static native int attributes(String path);

    static native String[] list(String path);

    static native long length(String path);

    static native long lastModified(String path);

    /** The whole file, or null when it is not a readable regular file inside the jail. */
    static native byte[] read(String path);
}
