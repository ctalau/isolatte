package java.lang;

import jdk.internal.mixin.MixinReplace;

/**
 * Mixin: miniJVM creates Class objects itself and keeps its class pointer in classHandle. TeaVM's
 * ClassInfo calls are retargeted to these ci$ natives (jni_teavm.c), and a Class is its own
 * ClassInfo.
 */
public final class Class<T> {
    private long classHandle;
    private ClassLoader classLoader;

    @MixinReplace
    static Class<?> createClass(Class<?> classInfo) {
        return classInfo;
    }

    /** TeaVM looks names up in the closed world it compiled; here classes load on demand. */
    @MixinReplace
    public static Class<?> forName(String name) throws ClassNotFoundException {
        return vm$forName(name, true, null);
    }

    @MixinReplace
    public static Class<?> forName(String name, boolean initialize, ClassLoader loader) throws ClassNotFoundException {
        return vm$forName(name, initialize, null);
    }

    static native Class<?> vm$forName(String name, boolean initialize, ClassLoader loader) throws ClassNotFoundException;

    static native Class<?> vm$getPrimitiveClass(String name);

    native int ci$modifiers();

    native int ci$primitiveKind();

    native String ci$name();

    native String ci$simpleName();

    native Class<?> ci$itemType();

    native Class<?> ci$arrayType();

    native Class<?> ci$declaringClass();

    native Class<?> ci$enclosingClass();

    native boolean ci$isSuperTypeOf(Class<?> subtype);

    native Class<?> ci$parent();

    native int ci$superinterfaceCount();

    native Class<?> ci$superinterface(int index);

    native int ci$enumConstantCount();

    native Object ci$enumConstant(int index);

    native Object ci$newArrayInstance(int length);

    native void ci$putItem(Object array, int index, Object value);

    native Object ci$getItem(Object array, int index);

    native int ci$arrayLength(Object array);

    native Object ci$newInstance();

    native boolean ci$initializeNewInstance(Object instance);

    native void ci$initialize();

    native org.teavm.runtime.reflect.ClassReflectionInfo ci$reflection();

    native Class<?> ci$classObject();
}
