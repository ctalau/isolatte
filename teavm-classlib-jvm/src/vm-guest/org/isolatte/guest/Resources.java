package org.isolatte.guest;

/** Class path resources, read by the VM (jni_teavm.c) from the boot class path jar. */
public final class Resources {
    private Resources() {
    }

    /** The resource's bytes, or null. Names that are absolute or contain ".." are refused. */
    public static native byte[] read(String name);
}
