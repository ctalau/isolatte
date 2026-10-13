package java.lang;

import jdk.internal.mixin.MixinProvided;
import jdk.internal.mixin.MixinReplace;

/** Mixin: stack traces come from miniJVM's frames (TeaVM's need a JS or C stack). */
public class Throwable {
    @MixinProvided
    private StackTraceElement[] stackTrace;

    @MixinReplace
    public Throwable fillInStackTrace() {
        StackTraceElement first = buildStackElement(Thread.currentThread());
        int n = 0;
        for (StackTraceElement e = first; e != null; e = e.parent) {
            n++;
        }
        StackTraceElement[] trace = new StackTraceElement[n];
        n = 0;
        for (StackTraceElement e = first; e != null; e = e.parent) {
            e.fixClassName();
            trace[n++] = e;
        }
        stackTrace = trace;
        return this;
    }

    private native StackTraceElement buildStackElement(Thread thread);
}
