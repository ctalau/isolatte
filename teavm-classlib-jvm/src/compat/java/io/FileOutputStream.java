package java.io;

import java.nio.channels.FileChannel;
import jdk.internal.io.MixinProvided;
import jdk.internal.io.VirtualFileAccessor;

/** Mixin: descriptor-backed streams for System.out/err and process pipes. See FileInputStream. */
public class FileOutputStream extends OutputStream {
    @MixinProvided
    private VirtualFileAccessor accessor;

    private FileDescriptor fd;

    static {
        initIDs();
    }

    private static native void initIDs();

    private native void writeBytes(byte[] b, int off, int len, boolean append) throws IOException;

    @MixinProvided
    public FileOutputStream(VirtualFileAccessor accessor) {
    }

    @MixinProvided
    public FileOutputStream(String name) throws FileNotFoundException {
    }

    public FileOutputStream(FileDescriptor fdObj) {
        if (fdObj == null) {
            throw new NullPointerException();
        }
        fd = fdObj;
        accessor = new DescriptorAccessor(this, fdObj);
    }

    void writeDescriptor(byte[] b, int off, int len) throws IOException {
        writeBytes(b, off, len, false);
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

    @MixinProvided
    public void write(int b) {
    }
}
