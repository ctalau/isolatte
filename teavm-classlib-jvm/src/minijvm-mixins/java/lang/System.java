package java.lang;

import jdk.internal.mixin.MixinReplace;

/** Mixin: array copies, clocks and identity hashes come from miniJVM's natives. */
public final class System {
    @MixinReplace
    public static native void arraycopy(Object src, int srcPos, Object dest, int destPos, int length);

    @MixinReplace
    static void doArrayCopy(Object src, int srcPos, Object dest, int destPos, int length) {
        arraycopy(src, srcPos, dest, destPos, length);
    }

    @MixinReplace
    public static native long nanoTime();

    @MixinReplace
    public static native int identityHashCode(Object x);

    /**
     * TeaVM returns a new, mostly empty SecurityManager; Java SE returns null when none is
     * installed (always, since JDK 18). Xerces calls checkPackageAccess on a non-null one.
     */
    @MixinReplace
    public static SecurityManager getSecurityManager() {
        return null;
    }
}
