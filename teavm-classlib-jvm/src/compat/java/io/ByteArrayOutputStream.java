package java.io;

import jdk.internal.io.MixinProvided;

/** Mixin: Java 11 method used by OpenJDK's crypto provider. */
public class ByteArrayOutputStream extends OutputStream {
    @MixinProvided
    public ByteArrayOutputStream() {
    }

    public void writeBytes(byte[] b) {
        write(b, 0, b.length);
    }

    @MixinProvided
    public void write(int b) {
    }

    @MixinProvided
    public void write(byte[] b, int off, int len) {
    }
}
