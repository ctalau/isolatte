package java.io;

import jdk.internal.io.MixinProvided;

/**
 * Mixin: host-file handles for the folder jail (java.io.HostFiles). These instances are not used as
 * TeaVM RandomAccessFiles; they only carry the {@code fd} field that libjava's natives operate on.
 */
public class RandomAccessFile {
    private static final int O_RDONLY = 1;

    private FileDescriptor fd;

    static {
        initIDs();
        SharedSecretsAccess.registerRandomAccessFile();
    }

    private static native void initIDs();

    private native void open0(String name, int mode) throws FileNotFoundException;

    private native int readBytes0(byte[] b, int off, int len) throws IOException;

    private native void seek0(long pos) throws IOException;

    private native long length0() throws IOException;

    @MixinProvided
    public RandomAccessFile(String name, String mode) {
    }

    private RandomAccessFile(FileDescriptor fd, String hostPath) throws FileNotFoundException {
        this.fd = fd;
        open0(hostPath, O_RDONLY);
    }

    /** Opens a host path read-only. Callers (HostFiles) must already have confined the path. */
    static RandomAccessFile openHost(String hostPath) throws FileNotFoundException {
        return new RandomAccessFile(new FileDescriptor(), hostPath);
    }

    int hostRead(byte[] b, int off, int len) throws IOException {
        return len == 0 ? 0 : readBytes0(b, off, len);
    }

    void hostSeek(long pos) throws IOException {
        seek0(pos);
    }

    long hostLength() throws IOException {
        return length0();
    }

    void hostClose() throws IOException {
        fd.close();
    }
}
