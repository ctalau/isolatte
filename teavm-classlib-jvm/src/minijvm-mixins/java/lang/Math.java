package java.lang;

import jdk.internal.mixin.MixinReplace;

/** Mixin: TeaVM's random() picks a per-backend native; miniJVM has one under this name. */
public final class Math {
    @MixinReplace
    public static native double random();
}
