import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.xerces.parsers.SAXParser;
import org.apache.xerces.util.XMLCatalogResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;

/**
 * Reference DTD validation with plain Xerces-J: one validating SAXParser per
 * thread, no grammar pool (so DTD-declared entities such as &amp;nbsp; are
 * known), DTDs resolved by public id through an OASIS catalog.
 *
 * usage: java -cp work-java:$CP XercesCheck THREADS CATALOG &lt; file-list
 * prints "INVALID path n" (plus the messages with VERBOSE=1) per invalid file.
 */
public class XercesCheck {
    public static void main(String[] args) throws Exception {
        int threads = Integer.parseInt(args[0]);
        String catalog = new File(args[1]).toURI().toString();
        boolean verbose = "1".equals(System.getenv("VERBOSE"));
        List<String> files = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(System.in, "UTF-8"))) {
            for (String l; (l = r.readLine()) != null; ) if (!l.isEmpty()) files.add(l);
        }
        String[] out = new String[files.size()];
        AtomicInteger next = new AtomicInteger();
        AtomicInteger invalid = new AtomicInteger();
        Thread[] ts = new Thread[threads];
        long t0 = System.nanoTime();
        for (int t = 0; t < threads; t++) {
            ts[t] = new Thread(() -> {
                try {
                    XMLCatalogResolver resolver = new XMLCatalogResolver(new String[] {catalog});
                    resolver.setPreferPublic(true);
                    SAXParser p = new SAXParser();
                    p.setFeature("http://xml.org/sax/features/validation", true);
                    p.setFeature("http://xml.org/sax/features/namespaces", false);
                    p.setProperty("http://apache.org/xml/properties/internal/entity-resolver", resolver);
                    List<String> msgs = new ArrayList<>();
                    p.setErrorHandler(new ErrorHandler() {
                        public void warning(SAXParseException e) {}
                        public void error(SAXParseException e) { msgs.add(e.getLineNumber() + ": " + e.getMessage()); }
                        public void fatalError(SAXParseException e) throws SAXParseException {
                            msgs.add(e.getLineNumber() + ": fatal: " + e.getMessage());
                            throw e;
                        }
                    });
                    for (int i; (i = next.getAndIncrement()) < out.length; ) {
                        msgs.clear();
                        try {
                            p.parse(new InputSource(new File(files.get(i)).toURI().toString()));
                        } catch (Exception e) {
                            if (msgs.isEmpty()) msgs.add("fatal: " + e);
                        }
                        if (!msgs.isEmpty()) {
                            invalid.incrementAndGet();
                            StringBuilder sb = new StringBuilder("INVALID " + files.get(i) + " " + msgs.size());
                            if (verbose) for (String m : msgs) sb.append("\n  ").append(m);
                            out[i] = sb.toString();
                        }
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            ts[t].start();
        }
        for (Thread t : ts) t.join();
        double s = (System.nanoTime() - t0) / 1e9;
        for (String o : out) if (o != null) System.out.println(o);
        System.out.printf("validator=xerces-plain threads=%d files=%d invalid_files=%d seconds=%.3f files_per_s=%.0f%n",
                threads, out.length, invalid.get(), s, out.length / s);
    }
}
