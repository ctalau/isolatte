package java.io;

import jdk.internal.io.VirtualFileAccessor;

/** Read-only VirtualFileAccessor over a host file opened with libjava's RandomAccessFile natives. */
final class HostFileAccessor implements VirtualFileAccessor {
    private final RandomAccessFile raf;
    // RandomAccessFile.getFilePointer is native in OpenJDK but a Java method in TeaVM, so the native
    // cannot be bound; the position is tracked here.
    private long position;

    HostFileAccessor(RandomAccessFile raf) {
        this.raf = raf;
    }

    @Override
    public int read(byte[] buffer, int offset, int limit) throws IOException {
        int n = Math.max(raf.hostRead(buffer, offset, limit), 0); // TeaVM's contract: 0 at end of file
        position += n;
        return n;
    }

    @Override
    public void write(byte[] buffer, int offset, int limit) throws IOException {
        throw new IOException("read-only file system");
    }

    @Override
    public int tell() throws IOException {
        return (int) position;
    }

    @Override
    public void seek(int target) throws IOException {
        raf.hostSeek(target);
        position = target;
    }

    @Override
    public void skip(int amount) throws IOException {
        seek((int) Math.min(position + amount, raf.hostLength()));
    }

    @Override
    public int size() throws IOException {
        return (int) Math.min(Integer.MAX_VALUE, raf.hostLength());
    }

    @Override
    public void resize(int size) throws IOException {
        throw new IOException("read-only file system");
    }

    @Override
    public void close() throws IOException {
        raf.hostClose();
    }

    @Override
    public void flush() {
    }
}
