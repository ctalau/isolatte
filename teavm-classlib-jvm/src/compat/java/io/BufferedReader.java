package java.io;

import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import jdk.internal.io.MixinProvided;
import jdk.internal.io.MixinReplace;

/** Mixin: lines() without TeaVM's internal stream implementation. */
public class BufferedReader extends Reader {
    @MixinProvided
    public BufferedReader(Reader in) {
    }

    @MixinReplace
    public Stream<String> lines() {
        return StreamSupport.stream(new BufferedReaderLines(this), false);
    }

    @MixinProvided
    public String readLine() throws IOException {
        return null;
    }

    @MixinProvided
    public int read(char[] cbuf, int off, int len) {
        return 0;
    }

    @MixinProvided
    public void close() {
    }
}
