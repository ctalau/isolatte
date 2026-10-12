package java.io;

import jdk.internal.io.HostAccess;
import jdk.internal.io.VirtualFileAccessor;

/**
 * Host primitives for the folder jail, built only on libjava's JNI natives: OpenJDK's own (unpatched)
 * java.io.UnixFileSystem for metadata, and the RandomAccessFile natives (added by the mixin) for
 * reading. NIO is not used: loading libnio itself goes through java.io.File.
 */
final class HostFiles extends HostAccess {
    private static final int ACCESS_READ = 0x04;
    private final UnixFileSystem fs = new UnixFileSystem();

    static {
        register(new HostFiles());
    }

    private HostFiles() {
    }

    /** A TeaVM File is a plain path holder here; UnixFileSystem's natives read its "path" field. */
    private static File file(String hostPath) {
        return new File(hostPath);
    }

    @Override
    public int attributes(String hostPath) {
        return fs.getBooleanAttributes(file(hostPath)) & (EXISTS | REGULAR | DIRECTORY);
    }

    @Override
    public String[] list(String hostPath) {
        return fs.list(file(hostPath));
    }

    @Override
    public long length(String hostPath) {
        return fs.getLength(file(hostPath));
    }

    @Override
    public long lastModified(String hostPath) {
        return fs.getLastModifiedTime(file(hostPath));
    }

    @Override
    public boolean canRead(String hostPath) {
        return fs.checkAccess(file(hostPath), ACCESS_READ);
    }

    @Override
    public String canonicalize(String hostPath) throws IOException {
        return fs.canonicalize(hostPath);
    }

    @Override
    public VirtualFileAccessor openRead(String hostPath) throws IOException {
        return new HostFileAccessor(RandomAccessFile.openHost(hostPath));
    }
}
