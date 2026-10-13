package org.isolatte.guest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.teavm.runtime.fs.VirtualFile;
import org.teavm.runtime.fs.VirtualFileAccessor;
import org.teavm.runtime.fs.VirtualFileSystem;

/**
 * A read-only TeaVM VirtualFileSystem over {@link Jail}: "/" is the jail folder. TeaVM's java.io
 * (and java.nio.file) are written against this interface, so they see nothing else.
 */
public final class JailFileSystem implements VirtualFileSystem {
    @Override
    public String getUserDir() {
        return "/";
    }

    @Override
    public boolean isWindows() {
        return false;
    }

    @Override
    public String[] getRoots() {
        return new String[] {"/"};
    }

    @Override
    public String canonicalize(String path) {
        List<String> parts = new ArrayList<>();
        for (String part : path.split("/")) {
            if (part.isEmpty() || part.equals(".")) {
                continue;
            }
            if (part.equals("..")) {
                if (!parts.isEmpty()) {
                    parts.remove(parts.size() - 1);
                }
            } else {
                parts.add(part);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            sb.append('/').append(p);
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    @Override
    public VirtualFile getFile(String path) {
        String virtual = canonicalize(path);
        return new Entry(virtual.substring(virtual.lastIndexOf('/') + 1), virtual);
    }

    private static final class Entry implements VirtualFile {
        private final String name;
        private final String path;

        Entry(String name, String path) {
            this.name = name;
            this.path = path;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean isDirectory() {
            return (Jail.attributes(path) & Jail.DIRECTORY) != 0;
        }

        @Override
        public boolean isFile() {
            return (Jail.attributes(path) & Jail.REGULAR) != 0;
        }

        @Override
        public String[] listFiles() {
            return Jail.list(path);
        }

        @Override
        public VirtualFileAccessor createAccessor(boolean readable, boolean writable, boolean append) {
            if (writable || append) {
                return null;
            }
            byte[] data = Jail.read(path);
            return data == null ? null : new BytesAccessor(data);
        }

        @Override
        public boolean createFile(String fileName) {
            return false;
        }

        @Override
        public boolean createDirectory(String fileName) {
            return false;
        }

        @Override
        public boolean delete() {
            return false;
        }

        @Override
        public boolean adopt(VirtualFile file, String fileName) {
            return false;
        }

        @Override
        public boolean canRead() {
            return Jail.attributes(path) != 0;
        }

        @Override
        public boolean canWrite() {
            return false;
        }

        @Override
        public long lastModified() {
            return Jail.lastModified(path);
        }

        @Override
        public boolean setLastModified(long lastModified) {
            return false;
        }

        @Override
        public boolean setReadOnly(boolean readOnly) {
            return false;
        }

        @Override
        public int length() {
            return (int) Math.min(Integer.MAX_VALUE, Jail.length(path));
        }
    }

    /** Reads a snapshot of the file taken when it was opened. */
    private static final class BytesAccessor implements VirtualFileAccessor {
        private final byte[] data;
        private int pos;

        BytesAccessor(byte[] data) {
            this.data = data;
        }

        @Override
        public int read(byte[] buffer, int offset, int limit) {
            int n = Math.min(limit, data.length - pos);
            if (n <= 0) {
                return limit == 0 ? 0 : -1;
            }
            System.arraycopy(data, pos, buffer, offset, n);
            pos += n;
            return n;
        }

        @Override
        public void write(byte[] buffer, int offset, int limit) throws IOException {
            throw new IOException("read-only");
        }

        @Override
        public int tell() {
            return pos;
        }

        @Override
        public void seek(int target) {
            pos = target;
        }

        @Override
        public void skip(int amount) {
            pos += amount;
        }

        @Override
        public int size() {
            return data.length;
        }

        @Override
        public void resize(int size) throws IOException {
            throw new IOException("read-only");
        }

        @Override
        public void close() {
        }

        @Override
        public void flush() {
        }
    }
}
