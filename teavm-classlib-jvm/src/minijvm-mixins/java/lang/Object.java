package java.lang;

import jdk.internal.mixin.MixinReplace;

/**
 * Mixin: miniJVM implements monitors, wait/notify, identity and cloning itself, so TeaVM's
 * versions (built on TeaVM's green threads and JavaScript object ids) become miniJVM natives.
 */
public class Object {
    @MixinReplace
    protected native Object clone() throws CloneNotSupportedException;

    @MixinReplace
    public final native void notify();

    @MixinReplace
    public final native void notifyAll();

    @MixinReplace
    public final native void wait(long timeout) throws InterruptedException;

    @MixinReplace
    final int identity() {
        return System.identityHashCode(this);
    }
}
