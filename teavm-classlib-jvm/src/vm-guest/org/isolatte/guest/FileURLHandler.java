package org.isolatte.guest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;

/**
 * {@code file:} URLs on top of java.io, i.e. on top of the jailed VirtualFileSystem. TeaVM's URL
 * only knows http(s) (via XHR) and has no file: handler; OpenJDK's FileURLConnection is likewise
 * plain java.io code. Other protocols keep TeaVM's handlers.
 */
public final class FileURLHandler extends URLStreamHandler implements URLStreamHandlerFactory {
    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        return protocol.equals("file") ? this : null;
    }

    @Override
    protected URLConnection openConnection(URL u) {
        return new Connection(u);
    }

    private static final class Connection extends URLConnection {
        private final File file;
        private InputStream in;

        Connection(URL url) {
            super(url);
            this.file = new File(URLDecoder.decode(url.getPath()));
        }

        @Override
        public void connect() throws IOException {
            if (in == null) {
                if (!file.isFile()) {
                    throw new FileNotFoundException(file.getPath());
                }
                in = new FileInputStream(file);
            }
        }

        @Override
        public InputStream getInputStream() throws IOException {
            connect();
            return in;
        }

        @Override
        public int getContentLength() {
            return (int) file.length();
        }

        @Override
        public long getLastModified() {
            return file.lastModified();
        }
    }
}
