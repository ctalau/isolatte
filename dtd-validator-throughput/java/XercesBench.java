// DTD-validate DITA topics with Xerces-J, all threads sharing one grammar pool.
//
// usage: java XercesBench THREADS MAPFILE flat|catalog CATALOG POOL [PASSES] < file-list
//   MAPFILE lines: PUBLIC-ID<TAB>flattened.dtd
//   flat:    DOCTYPE public ids resolve to the flattened DTDs (same input as the
//            other validators)
//   catalog: public ids resolve through the DITA-OT catalog to the original
//            modular DTDs
//   POOL:    stock-locked  XMLGrammarPoolImpl, DTDs preparsed, then locked
//            stock         XMLGrammarPoolImpl, DTDs preparsed, left open so
//                          documents can add grammars
//            publicid      XMLGrammarPoolImpl keyed by DOCTYPE public id (as
//                          DITA-OT's XMLGrammarPoolImplUtils does), preparsed,
//                          then locked
//
// PASSES (default 1) re-validates the whole list in the same JVM, printing one
// line per pass: pass 1 is a cold JVM, later passes show JIT-warmed speed.
//
// Stock Xerces keys a DTD grammar by its expanded system id (the DOCTYPE
// system id resolved against the *document*) and root name, so a preparsed
// grammar never matches, and an open pool holds one copy per directory and
// root element.

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import org.apache.xerces.parsers.SAXParser;
import org.apache.xerces.parsers.XIncludeAwareParserConfiguration;
import org.apache.xerces.parsers.XMLGrammarPreparser;
import org.apache.xerces.util.SynchronizedSymbolTable;
import org.apache.xerces.util.SymbolTable;
import org.apache.xerces.util.XMLCatalogResolver;
import org.apache.xerces.util.XMLGrammarPoolImpl;
import org.apache.xerces.xni.XMLResourceIdentifier;
import org.apache.xerces.xni.grammars.XMLGrammarDescription;
import org.apache.xerces.xni.parser.XMLEntityResolver;
import org.apache.xerces.xni.parser.XMLInputSource;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;

public class XercesBench {
    static final String POOL = "http://apache.org/xml/properties/internal/grammar-pool";
    static final String RESOLVER = "http://apache.org/xml/properties/internal/entity-resolver";

    /** A grammar pool that identifies DTDs by public id alone. */
    static class PublicIdGrammarPool extends XMLGrammarPoolImpl {
        @Override
        public boolean equals(XMLGrammarDescription a, XMLGrammarDescription b) {
            String pa = a.getPublicId(), pb = b.getPublicId();
            if (pa != null && pb != null) return a.getGrammarType().equals(b.getGrammarType()) && pa.equals(pb);
            return super.equals(a, b);
        }

        @Override
        public int hashCode(XMLGrammarDescription d) {
            return d.getPublicId() != null ? d.getPublicId().hashCode() : super.hashCode(d);
        }
    }

    /** Maps a DOCTYPE public id to its flattened DTD. */
    static XMLEntityResolver flatResolver(Map<String, String> map, AtomicInteger dtdLoads) {
        return (XMLResourceIdentifier id) -> {
            String f = id.getPublicId() == null ? null : map.get(id.getPublicId());
            if (f == null) return null;
            dtdLoads.incrementAndGet();
            return new XMLInputSource(id.getPublicId(), new File(f).toURI().toString(), null);
        };
    }

    /** Catalog resolver that also counts how often a DTD is actually fetched. */
    static XMLEntityResolver catalogResolver(String catalog, AtomicInteger dtdLoads) {
        XMLCatalogResolver cat = new XMLCatalogResolver(new String[] {new File(catalog).toURI().toString()});
        cat.setPreferPublic(true);
        return (XMLResourceIdentifier id) -> {
            XMLInputSource in = cat.resolveEntity(id);
            if (in != null && in.getSystemId() != null && in.getSystemId().endsWith(".dtd")) dtdLoads.incrementAndGet();
            return in;
        };
    }

    public static void main(String[] args) throws Exception {
        int nthreads = Integer.parseInt(args[0]);
        Map<String, String> map = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Paths.get(args[1]))) {
            String[] kv = line.split("\t");
            if (kv.length == 2) map.put(kv[0], kv[1]);
        }
        boolean flat = args[2].equals("flat");
        List<String> files = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(System.in))) {
            for (String l; (l = r.readLine()) != null; ) files.add(l);
        }

        long t0 = System.nanoTime();
        SymbolTable symbols = new SynchronizedSymbolTable();
        String poolMode = args[4];
        XMLGrammarPoolImpl pool = poolMode.equals("publicid") ? new PublicIdGrammarPool() : new XMLGrammarPoolImpl();
        AtomicInteger dtdLoads = new AtomicInteger();
        XMLEntityResolver resolver = flat ? flatResolver(map, dtdLoads) : catalogResolver(args[3], dtdLoads);

        XMLGrammarPreparser pre = new XMLGrammarPreparser(symbols);
        pre.registerPreparser(XMLGrammarDescription.XML_DTD, null);
        pre.setGrammarPool(pool);
        pre.setEntityResolver(resolver);
        for (String pub : map.keySet()) {
            XMLInputSource in = resolver.resolveEntity(new org.apache.xerces.util.XMLResourceIdentifierImpl(pub, "topic.dtd", null, null));
            pre.preparseGrammar(XMLGrammarDescription.XML_DTD, in);
        }
        if (!poolMode.equals("stock")) pool.lockPool();
        int preloadLoads = dtdLoads.get();
        double loadS = (System.nanoTime() - t0) / 1e9;
        int passes = args.length > 5 ? Integer.parseInt(args[5]) : 1;
        for (int pass = 1; pass <= passes; pass++) {
            runPass(pass, nthreads, files, symbols, pool, resolver, dtdLoads, preloadLoads, loadS, poolMode, flat);
        }
    }

    static void runPass(int pass, int nthreads, List<String> files, SymbolTable symbols, XMLGrammarPoolImpl pool,
                        XMLEntityResolver resolver, AtomicInteger dtdLoads, int preloadLoads, double loadS,
                        String poolMode, boolean flat) throws Exception {

        AtomicInteger next = new AtomicInteger();
        AtomicLong bytes = new AtomicLong();
        AtomicInteger invalid = new AtomicInteger(), errors = new AtomicInteger();
        CyclicBarrier ready = new CyclicBarrier(nthreads + 1);
        Thread[] th = new Thread[nthreads];
        for (int t = 0; t < nthreads; t++) {
            th[t] = new Thread(() -> {
                try {
                    XIncludeAwareParserConfiguration cfg = new XIncludeAwareParserConfiguration(symbols, pool);
                    cfg.setProperty(RESOLVER, resolver);
                    SAXParser parser = new SAXParser(cfg);
                    parser.setFeature("http://xml.org/sax/features/validation", true);
                    int[] count = new int[1];
                    parser.setErrorHandler(new ErrorHandler() {
                        public void warning(SAXParseException e) {}
                        public void error(SAXParseException e) { count[0]++; }
                        public void fatalError(SAXParseException e) throws SAXParseException { count[0]++; throw e; }
                    });
                    ready.await();
                    for (int i; (i = next.getAndIncrement()) < files.size(); ) {
                        File f = new File(files.get(i));
                        bytes.addAndGet(f.length());
                        count[0] = 0;
                        try {
                            parser.parse(new InputSource(f.toURI().toString()));
                        } catch (Exception e) {
                            if (count[0] == 0) count[0] = 1;
                        }
                        if (count[0] > 0) {
                            invalid.incrementAndGet();
                            errors.addAndGet(count[0]);
                            synchronized (System.out) { System.out.println("INVALID " + files.get(i) + " " + count[0]); }
                        }
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            th[t].start();
        }
        ready.await();
        long t1 = System.nanoTime();
        for (Thread t : th) t.join();
        double s = (System.nanoTime() - t1) / 1e9;
        System.out.printf(Locale.ROOT,
            "validator=xerces-%s-%s pass=%d threads=%d files=%d bytes=%d invalid_files=%d errors=%d "
            + "dtd_load_s=%.3f seconds=%.3f files_per_s=%.0f MB_per_s=%.1f dtd_fetches_after_preload=%d grammars_in_pool=%d%n",
            poolMode, flat ? "flat" : "catalog", pass, nthreads, files.size(), bytes.get(), invalid.get(), errors.get(),
            loadS, s, files.size() / s, bytes.get() / s / 1e6, dtdLoads.get() - preloadLoads,
            pool.retrieveInitialGrammarSet(XMLGrammarDescription.XML_DTD).length);
    }
}
