package org.isolatte.c;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.teavm.interop.Import;
import org.teavm.interop.c.Include;
import org.teavm.interop.Unmanaged;
import org.teavm.runtime.fs.VirtualFile;
import org.teavm.runtime.fs.VirtualFileAccessor;
import org.teavm.runtime.fs.VirtualFileSystem;

/**
 * Read-only view of one host folder, installed under java.io. "/" inside the program is the folder.
 * Every path is normalized lexically (".." stops at "/") and mapped under the folder. Symbolic links
 * are never followed: each component below the folder is checked with readlink(2), and a path with a
 * symlink anywhere in it does not exist. So no host path outside the folder is ever passed to the OS.
 */
public final class JailFileSystem implements VirtualFileSystem {
    private final VirtualFileSystem host;
    private final String root;
    private final byte[] linkBuf = new byte[1];

    /** @param hostRoot absolute path of the folder; it is trusted configuration and used as given. */
    public JailFileSystem(VirtualFileSystem host, String hostRoot) {
        if (!hostRoot.startsWith("/")) throw new IllegalArgumentException("jail root must be absolute: " + hostRoot);
        this.host = host;
        String n = normalize(hostRoot);
        this.root = n.equals("/") ? "" : n;
    }

    public String root() {
        return root.isEmpty() ? "/" : root;
    }

    @Override public String getUserDir() { return "/"; }
    @Override public boolean isWindows() { return false; }
    @Override public String canonicalize(String path) { return path; }
    @Override public String[] getRoots() { return new String[] { "" }; }

    @Override
    public VirtualFile getFile(String path) {
        String virtual = normalize(path);
        StringBuilder cur = new StringBuilder(root);
        int from = 1;
        while (from <= virtual.length()) {
            int slash = virtual.indexOf('/', from);
            if (slash < 0) slash = virtual.length();
            if (slash > from) {
                cur.append('/').append(virtual, from, slash);
                if (isSymlink(cur.toString())) return new Missing(virtual);
            }
            from = slash + 1;
        }
        return new ReadOnly(host.getFile(root + virtual.substring(virtual.equals("/") ? 1 : 0)), virtual);
    }

    static String normalize(String path) {
        List<String> parts = new ArrayList<>();
        for (String part : path.split("/")) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (part.equals("..")) {
                if (!parts.isEmpty()) parts.remove(parts.size() - 1);
            } else {
                parts.add(part);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String part : parts) sb.append('/').append(part);
        return sb.length() == 0 ? "/" : sb.toString();
    }

    /** readlink(2) succeeds only on a symlink; on a regular file/dir or a missing path it fails. */
    private boolean isSymlink(String hostPath) {
        byte[] in = (hostPath + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return readlink(in, linkBuf, 1) >= 0;
    }

    @Import(name = "readlink")
    @Include("unistd.h")
    @Unmanaged
    private static native long readlink(byte[] path, byte[] buf, long size);

    private static final class ReadOnly implements VirtualFile {
        private final VirtualFile real;
        private final String virtual;

        ReadOnly(VirtualFile real, String virtual) { this.real = real; this.virtual = virtual; }

        @Override public String getName() { return virtual.substring(virtual.lastIndexOf('/') + 1); }
        @Override public boolean isDirectory() { return real.isDirectory(); }
        @Override public boolean isFile() { return real.isFile(); }
        @Override public String[] listFiles() { return real.listFiles(); }
        @Override public VirtualFileAccessor createAccessor(boolean readable, boolean writable, boolean append) {
            return writable || append ? null : real.createAccessor(true, false, false);
        }
        @Override public boolean createFile(String fileName) throws IOException { throw new IOException("read-only"); }
        @Override public boolean createDirectory(String fileName) { return false; }
        @Override public boolean delete() { return false; }
        @Override public boolean adopt(VirtualFile file, String fileName) { return false; }
        @Override public boolean canRead() { return real.canRead(); }
        @Override public boolean canWrite() { return false; }
        @Override public long lastModified() { return real.lastModified(); }
        @Override public boolean setLastModified(long lastModified) { return false; }
        @Override public boolean setReadOnly(boolean readOnly) { return false; }
        @Override public int length() { return real.length(); }
    }

    private static final class Missing implements VirtualFile {
        private final String virtual;
        Missing(String virtual) { this.virtual = virtual; }

        @Override public String getName() { return virtual.substring(virtual.lastIndexOf('/') + 1); }
        @Override public boolean isDirectory() { return false; }
        @Override public boolean isFile() { return false; }
        @Override public String[] listFiles() { return null; }
        @Override public VirtualFileAccessor createAccessor(boolean readable, boolean writable, boolean append) { return null; }
        @Override public boolean createFile(String fileName) throws IOException { throw new IOException("read-only"); }
        @Override public boolean createDirectory(String fileName) { return false; }
        @Override public boolean delete() { return false; }
        @Override public boolean adopt(VirtualFile file, String fileName) { return false; }
        @Override public boolean canRead() { return false; }
        @Override public boolean canWrite() { return false; }
        @Override public long lastModified() { return 0; }
        @Override public boolean setLastModified(long lastModified) { return false; }
        @Override public boolean setReadOnly(boolean readOnly) { return false; }
        @Override public int length() { return 0; }
    }
}
