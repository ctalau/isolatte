package java.io;

import jdk.internal.io.VirtualFileAccessor;

/**
 * VirtualFileAccessor over an already-open descriptor (System.in/out/err, process pipes), using
 * libjava's FileInputStream/FileOutputStream natives. It cannot open anything by name.
 */
final class DescriptorAccessor implements VirtualFileAccessor {
    private final FileInputStream in;
    private final FileOutputStream out;
    private final FileDescriptor fd;

    DescriptorAccessor(FileInputStream in, FileDescriptor fd) {
        this.in = in;
        this.out = null;
        this.fd = fd;
    }

    DescriptorAccessor(FileOutputStream out, FileDescriptor fd) {
        this.in = null;
        this.out = out;
        this.fd = fd;
    }

    @Override
    public int read(byte[] buffer, int offset, int limit) throws IOException {
        if (in == null) {
            throw new IOException("write-only descriptor");
        }
        return Math.max(in.readDescriptor(buffer, offset, limit), 0); // 0 at end of stream
    }

    @Override
    public void write(byte[] buffer, int offset, int limit) throws IOException {
        if (out == null) {
            throw new IOException("read-only descriptor");
        }
        out.writeDescriptor(buffer, offset, limit);
    }

    // TeaVM's available() is size() - tell().
    @Override
    public int tell() {
        return 0;
    }

    @Override
    public int size() throws IOException {
        return in == null ? 0 : in.availableDescriptor();
    }

    @Override
    public void seek(int target) throws IOException {
        throw new IOException("descriptor is not seekable");
    }

    @Override
    public void skip(int amount) throws IOException {
        byte[] scratch = new byte[Math.min(Math.max(amount, 1), 8192)];
        while (amount > 0) {
            int n = read(scratch, 0, Math.min(amount, scratch.length));
            if (n == 0) {
                return;
            }
            amount -= n;
        }
    }

    @Override
    public void resize(int size) throws IOException {
        throw new IOException("descriptor cannot be resized");
    }

    @Override
    public void close() throws IOException {
        fd.close();
    }

    @Override
    public void flush() {
    }
}
