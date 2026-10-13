package java.io;

import jdk.internal.io.MixinProvided;

/** Mixin: constructor used by OpenJDK's FilterWriter (not in TeaVM) to share the lock. */
public abstract class Writer {
    @MixinProvided
    protected Object lock;

    @MixinProvided
    protected Writer(Object lock) {
    }

    Writer(Writer writer) {
        this((Object) writer);
    }
}
