package java.io;

import jdk.internal.io.MixinProvided;
import jdk.internal.io.MixinReplace;

/**
 * Mixin: OpenJDK's System.out/err are autoflushing PrintStreams over an 8 KiB BufferedOutputStream and
 * are not flushed at exit. TeaVM's PrintStream honours autoFlush only in write(int), so print/println
 * output stayed buffered and was lost. Also registers the SharedSecrets lock accessor used by
 * Throwable.printStackTrace, and adds the file-name constructor used by CDS diagnostics.
 */
public class PrintStream extends FilterOutputStream {
    static {
        SharedSecretsAccess.registerPrintStream();
    }

    @MixinProvided
    private boolean autoFlush;

    @MixinProvided
    private boolean errorState;

    @MixinProvided
    public PrintStream(OutputStream out) {
        super(out);
    }

    public PrintStream(String fileName) throws FileNotFoundException {
        this(new FileOutputStream(fileName));
    }

    /** TeaVM's body plus OpenJDK's "flush after writing an array when autoFlush" rule. */
    @MixinReplace
    public void write(byte[] b, int off, int len) {
        if (!check()) {
            return;
        }
        try {
            out.write(b, off, len);
        } catch (IOException e) {
            errorState = true;
        }
        if (autoFlush && !errorState) {
            flush();
        }
    }

    @MixinProvided
    private boolean check() {
        return false;
    }

    @MixinProvided
    public void flush() {
    }
}
