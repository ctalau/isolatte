package jdk.internal.io;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A read-only VirtualFileSystem whose root "/" is one host folder.
 *
 * <p>Virtual paths are normalized lexically first, so ".." cannot climb above "/". The host path is
 * then canonicalized (symlinks resolved); a result outside the folder is treated as nonexistent, so a
 * symlink inside the folder cannot point out of it. Operations use the canonical host path. There is
 * no O_NOFOLLOW in libjava's open, so a component swapped for a symlink between the check and the
 * open (a TOCTOU race by another host process) is not prevented.
 *
 * <p>OpenJDK's own java.base code also uses java.io for its runtime files, so two further views
 * exist, at their host paths (they shadow the same paths in the folder):
 * <ul>
 * <li>{@code ${java.home}/lib}, read-only, confined like the folder: e.g. {@code tzdb.dat}, read by
 *     TimeZone when a file: URLConnection formats its Last-Modified header;</li>
 * <li>the existence (not the contents) of {@code lib*.so} directly in {@code sun.boot.library.path}:
 *     jdk.internal.loader.NativeLibraries checks {@code File.exists()} before its native dlopen, so
 *     without it libnio cannot load and the boot layer fails.</li>
 * </ul>
 */
final class FolderFileSystem implements VirtualFileSystem {
    private final String root;
    private final String runtime;
    private final String runtimeVirtual;
    private final List<String> libraryDirs;
    private final HostAccess host;

    /** {@code folder == null}: no folder is visible, only the JDK's runtime files. */
    FolderFileSystem(String folder, String javaHome, List<String> libraryDirs, HostAccess host) {
        this.host = host;
        this.libraryDirs = List.copyOf(libraryDirs);
        // Only string operations here: this runs inside java.io.File's static initializer, so File
        // objects cannot be used yet. A root that is not a directory simply shows nothing.
        this.root = folder == null ? null : canonicalHost(folder);
        // Matched as the JDK spells it (java.home may contain symlinks), confined to the real path.
        this.runtimeVirtual = javaHome == null ? null : canonicalize(javaHome + "/lib");
        this.runtime = javaHome == null ? null : canonicalHost(javaHome + "/lib");
    }

    private String canonicalHost(String path) {
        try {
            return host.canonicalize(path);
        } catch (IOException e) {
            throw new IllegalArgumentException(path, e);
        }
    }

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
        return "/" + String.join("/", parts);
    }

    @Override
    public VirtualFile getFile(String path) {
        String virtual = canonicalize(path);
        String name = virtual.substring(virtual.lastIndexOf('/') + 1);
        String dir = virtual.substring(0, virtual.lastIndexOf('/'));
        if (runtime != null && within(virtual, runtimeVirtual)) {
            return new Entry(name, confine(virtual, runtime), true);
        }
        if (name.startsWith("lib") && name.endsWith(".so") && libraryDirs.contains(dir)) {
            return new Entry(name, virtual, false);
        }
        if (root == null) {
            return new Entry(name, null, false);
        }
        return new Entry(name, confine(virtual.equals("/") ? root : root + virtual, root), true);
    }

    /** The canonical host path, or null when it resolves outside {@code hostRoot}. */
    private String confine(String hostPath, String hostRoot) {
        try {
            String real = host.canonicalize(hostPath);
            return within(real, hostRoot) ? real : null;
        } catch (IOException e) {
            return null;
        }
    }

    private static boolean within(String path, String dir) {
        return path.equals(dir) || path.startsWith(dir.endsWith("/") ? dir : dir + "/");
    }

    /**
     * A virtual file; {@code hostPath == null} means outside the folder, i.e. nonexistent. Without
     * {@code contents}, only existence and metadata are visible (native libraries).
     */
    private final class Entry implements VirtualFile {
        private final String name;
        private final String hostPath;
        private final boolean contents;

        Entry(String name, String hostPath, boolean contents) {
            this.name = name;
            this.hostPath = hostPath;
            this.contents = contents;
        }

        private int attributes() {
            return hostPath == null ? 0 : host.attributes(hostPath);
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean isDirectory() {
            return (attributes() & HostAccess.DIRECTORY) != 0;
        }

        @Override
        public boolean isFile() {
            return (attributes() & HostAccess.REGULAR) != 0;
        }

        @Override
        public String[] listFiles() {
            return contents && isDirectory() ? host.list(hostPath) : null;
        }

        @Override
        public VirtualFileAccessor createAccessor(boolean readable, boolean writable, boolean append) {
            if (writable || append || !contents || !isFile()) {
                return null;
            }
            try {
                return host.openRead(hostPath);
            } catch (IOException e) {
                return null;
            }
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
            return contents && hostPath != null && host.canRead(hostPath);
        }

        @Override
        public boolean canWrite() {
            return false;
        }

        @Override
        public long lastModified() {
            return hostPath == null ? 0 : host.lastModified(hostPath);
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
            return hostPath == null ? 0 : (int) Math.min(Integer.MAX_VALUE, host.length(hostPath));
        }
    }
}
