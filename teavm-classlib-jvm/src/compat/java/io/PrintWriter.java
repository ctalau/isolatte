package java.io;

import jdk.internal.io.MixinProvided;

/** Mixin: registers the SharedSecrets lock accessor, as OpenJDK's PrintWriter does. */
public class PrintWriter extends Writer {
    static {
        SharedSecretsAccess.registerPrintWriter();
    }

    @MixinProvided
    public PrintWriter(Writer out) {
        super(out);
    }
}
