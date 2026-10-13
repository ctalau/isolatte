package org.isolatte.bench;

import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.parsers.XIncludeAwareParserConfiguration;
import org.w3c.dom.Document;

/** Parses one document (with XInclude) repeatedly with Xerces, timed inside the guest. */
public final class XmlBench {
    public static void main(String[] args) throws Exception {
        String uri = args[0];
        int rounds = args.length > 1 ? Integer.parseInt(args[1]) : 5;
        int elements = 0;
        for (int r = 0; r < rounds; r++) {
            long t0 = System.nanoTime();
            DOMParser parser = new DOMParser(new XIncludeAwareParserConfiguration());
            parser.setFeature("http://apache.org/xml/features/xinclude", true);
            parser.parse(uri);
            Document doc = parser.getDocument();
            elements = doc.getElementsByTagName("*").getLength();
            long t1 = System.nanoTime();
            System.out.println("round " + r + ": " + (t1 - t0) / 1000000 + " ms");
        }
        System.out.println("elements " + elements);
    }

    private XmlBench() {
    }
}
