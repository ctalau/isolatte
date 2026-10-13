package org.isolatte.c;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.nio.charset.StandardCharsets;

/**
 * TeaVM's java.net.URL only knows an XMLHttpRequest handler, which does not exist in C. This factory
 * gives "file:" URLs a connection that reads through java.io (so through the jail), and gives every
 * other scheme a handler that refuses to connect.
 */
public final class FileUrlHandlers implements URLStreamHandlerFactory {
    @Override
    public URLStreamHandler createURLStreamHandler(String protocol) {
        return protocol.equals("file") ? new FileHandler() : new DenyHandler();
    }

    private static final class FileHandler extends URLStreamHandler {
        @Override
        protected URLConnection openConnection(URL u) {
            return new FileConnection(u);
        }
    }

    private static final class DenyHandler extends URLStreamHandler {
        @Override
        protected URLConnection openConnection(URL u) throws IOException {
            throw new IOException("scheme not supported in this build: " + u.getProtocol());
        }
    }

    private static final class FileConnection extends URLConnection {
        FileConnection(URL url) { super(url); }

        @Override public void connect() { connected = true; }

        @Override
        public InputStream getInputStream() throws IOException {
            connect();
            return new FileInputStream(decode(url.getPath()));
        }
    }

    static String decode(String path) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] raw = path.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == '%' && i + 2 < raw.length) {
                out.write(Integer.parseInt(new String(raw, i + 1, 2, StandardCharsets.US_ASCII), 16));
                i += 2;
            } else {
                out.write(raw[i]);
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    public FileUrlHandlers() { }
}
