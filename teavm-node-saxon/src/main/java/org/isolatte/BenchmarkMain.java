package org.isolatte;

/** JVM-only benchmark driver; file I/O is outside the timed region. */
public final class BenchmarkMain {
    public static void main(String[] args) throws Exception {
        String stylesheet = java.nio.file.Files.readString(java.nio.file.Path.of(args[0]));
        String xml = java.nio.file.Files.readString(java.nio.file.Path.of(args[1]));
        System.out.println(TransformXml.benchmark(stylesheet, xml,
            Integer.parseInt(args[2]), Integer.parseInt(args[3]), Boolean.parseBoolean(args[4])));
    }
}
