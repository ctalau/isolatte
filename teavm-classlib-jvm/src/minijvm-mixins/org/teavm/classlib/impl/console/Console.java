package org.teavm.classlib.impl.console;

import jdk.internal.mixin.MixinReplace;

/** Mixin: console output through jni_teavm.c (TeaVM's goes to JavaScript or C runtime functions). */
public final class Console {
    @MixinReplace
    public static native void writeStderr(byte[] data, int off, int len);

    @MixinReplace
    public static native void writeStdout(byte[] data, int off, int len);
}
