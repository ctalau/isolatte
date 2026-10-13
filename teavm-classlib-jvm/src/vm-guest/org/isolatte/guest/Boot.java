package org.isolatte.guest;

import java.net.URL;
import org.teavm.runtime.fs.VirtualFileSystemProvider;

/** Run by the VM before main when a jail is configured. */
public final class Boot {
    private Boot() {
    }

    public static void init() {
        VirtualFileSystemProvider.setInstance(new JailFileSystem());
        URL.setURLStreamHandlerFactory(new FileURLHandler());
    }
}
