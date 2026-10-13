package java.io;

import jdk.internal.access.JavaIOPrintStreamAccess;
import jdk.internal.access.JavaIOPrintWriterAccess;
import jdk.internal.access.JavaIORandomAccessFileAccess;
import jdk.internal.access.SharedSecrets;

/**
 * The SharedSecrets accessors that OpenJDK's PrintStream, PrintWriter and RandomAccessFile register
 * in their static initializers; TeaVM's classes do not. Throwable.printStackTrace needs the locks.
 */
final class SharedSecretsAccess implements JavaIOPrintStreamAccess, JavaIOPrintWriterAccess,
        JavaIORandomAccessFileAccess {
    private static final SharedSecretsAccess INSTANCE = new SharedSecretsAccess();

    static void registerPrintStream() {
        SharedSecrets.setJavaIOCPrintStreamAccess(INSTANCE);
    }

    static void registerPrintWriter() {
        SharedSecrets.setJavaIOCPrintWriterAccess(INSTANCE);
    }

    static void registerRandomAccessFile() {
        SharedSecrets.setJavaIORandomAccessFileAccess(INSTANCE);
    }

    /** TeaVM's PrintStream synchronizes on itself. */
    @Override
    public Object lock(PrintStream ps) {
        return ps;
    }

    @Override
    public Object lock(PrintWriter pw) {
        return pw.lock;
    }

    /** Used by ZipFile's OPEN_DELETE mode; the folder file system is read-only. */
    @Override
    public RandomAccessFile openAndDelete(File file, String mode) throws IOException {
        throw new IOException("open-and-delete is not supported by the virtual file system: " + file);
    }
}
