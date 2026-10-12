package java.io;

import java.nio.channels.FileChannel;
import jdk.internal.io.MixinProvided;
import jdk.internal.io.MixinReplace;
import jdk.internal.io.VirtualFileAccessor;

/**
 * Mixin: descriptor-backed streams. OpenJDK's System.initPhase1 builds System.in from
 * {@code new FileInputStream(FileDescriptor.in)}; libjava's natives read the {@code fd} field.
 * Also fixes TeaVM's read(), which returns the byte sign-extended (0xFF reads as -1, i.e. EOF) and
 * uses a static one-byte buffer shared by all streams and threads.
 */
public class FileInputStream extends InputStream {
    @MixinProvided
    private VirtualFileAccessor accessor;

    /** Set only for descriptor-backed streams. Field name and type are fixed by libjava's initIDs. */
    private FileDescriptor fd;

    static {
        initIDs();
    }

    private static native void initIDs();

    private native int readBytes(byte[] b, int off, int len) throws IOException;

    private native int available0() throws IOException;

    @MixinProvided
    public FileInputStream(VirtualFileAccessor accessor) {
    }

    public FileInputStream(FileDescriptor fdObj) {
        if (fdObj == null) {
            throw new NullPointerException();
        }
        fd = fdObj;
        accessor = new DescriptorAccessor(this, fdObj);
    }

    int readDescriptor(byte[] b, int off, int len) throws IOException {
        return len == 0 ? 0 : readBytes(b, off, len);
    }

    int availableDescriptor() throws IOException {
        return available0();
    }

    public final FileDescriptor getFD() throws IOException {
        if (fd == null) {
            throw new IOException("virtual file has no host descriptor");
        }
        return fd;
    }

    public FileChannel getChannel() {
        throw new UnsupportedOperationException("FileChannel is not available for virtual files");
    }

    @MixinReplace
    public int read() throws IOException {
        ensureOpened();
        byte[] b = new byte[1];
        return accessor.read(b, 0, 1) != 0 ? b[0] & 0xFF : -1;
    }

    @MixinProvided
    private void ensureOpened() {
    }
}
