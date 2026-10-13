package java.io;

import java.nio.file.Path;
import jdk.internal.io.MixinProvided;

/** Mixin: members of OpenJDK's File that other java.base classes call. */
public class File {
    @MixinProvided
    private String path;

    @MixinProvided
    public File(String path) {
    }

    /** Called by OpenJDK's UnixFileSystem. */
    final boolean isInvalid() {
        return path.indexOf('\u0000') >= 0;
    }

    /** Called by OpenJDK's UnixFileSystem: length of the "/" prefix of an absolute path. */
    int getPrefixLength() {
        return path.startsWith("/") ? 1 : 0;
    }

    /**
     * A virtual file has no NIO counterpart: the default NIO file system is the unrestricted host, so
     * mapping to it would bypass the folder jail.
     */
    public Path toPath() {
        throw new UnsupportedOperationException("java.io.File is virtual (TeaVM file system); no NIO Path");
    }
}
