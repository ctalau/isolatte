package java.lang;

import jdk.internal.mixin.MixinProvided;

/**
 * Mixin: miniJVM builds stack traces as a linked list of StackTraceElements created with a
 * no-argument constructor, filling these fields from C.
 */
public final class StackTraceElement {
    @MixinProvided
    private String declaringClass;

    StackTraceElement parent;
    Class<?> declaringClazz;

    StackTraceElement() {
    }

    /** miniJVM writes internal names (java/lang/String). */
    void fixClassName() {
        if (declaringClass != null) {
            declaringClass = declaringClass.replace('/', '.');
        }
    }
}
