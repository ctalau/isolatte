package jdk.internal.io;

import java.util.List;

/**
 * Mixin for TeaVM's VirtualFileSystemProvider. TeaVM's default is an empty in-memory file system,
 * with which HotSpot cannot even load libnio. Here the property {@code jdk.internal.io.vfs.root}
 * selects the host folder that java.io sees, from the first java.io.File the JDK creates, so the jail
 * is in place before any application code runs and applications need no access to this package.
 * Without the property no folder is visible. See FolderFileSystem for the JDK runtime files that are
 * visible in addition.
 */
public final class VirtualFileSystemProvider {
    @MixinProvided
    private VirtualFileSystemProvider() {
    }

    private static boolean creating;

    @MixinReplace
    private static VirtualFileSystem create() {
        if (creating) {
            // Setting up the folder creates java.io.File objects, whose static initializer asks the
            // provider for isWindows(). The outer call replaces this placeholder when it returns.
            return new InMemoryVirtualFileSystem();
        }
        creating = true;
        try {
            String root = System.getProperty("jdk.internal.io.vfs.root");
            String libraryPath = System.getProperty("sun.boot.library.path", "");
            return new FolderFileSystem(root, System.getProperty("java.home"),
                    List.of(libraryPath.split(":")), HostAccess.get());
        } finally {
            creating = false;
        }
    }
}
