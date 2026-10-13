package java.lang;

/** Mixin: miniJVM keeps the thread's interpreter state in stackFrame (and a char[] name, added by the builder). */
public class Thread {
    private long stackFrame;

    @jdk.internal.mixin.MixinProvided
    public static Thread currentThread() {
        return null;
    }
}
