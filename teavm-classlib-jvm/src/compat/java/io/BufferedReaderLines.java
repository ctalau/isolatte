package java.io;

import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;

/** BufferedReader.lines() source; TeaVM's version is built on its own stream implementation. */
final class BufferedReaderLines extends Spliterators.AbstractSpliterator<String> {
    private final BufferedReader reader;

    BufferedReaderLines(BufferedReader reader) {
        super(Long.MAX_VALUE, Spliterator.ORDERED | Spliterator.NONNULL);
        this.reader = reader;
    }

    @Override
    public boolean tryAdvance(Consumer<? super String> action) {
        String line;
        try {
            line = reader.readLine();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (line == null) {
            return false;
        }
        action.accept(line);
        return true;
    }
}
