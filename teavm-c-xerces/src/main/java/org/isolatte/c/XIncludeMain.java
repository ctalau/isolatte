package org.isolatte.c;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.parsers.XIncludeAwareParserConfiguration;
import org.teavm.backend.c.runtime.fs.CFileSystem;
import org.teavm.runtime.fs.VirtualFileSystemProvider;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXParseException;

/**
 * usage: xi [--no-jail] [--bench N] [--probe] ROOT SYSTEM-ID...
 * Parses each system ID with Xerces (XInclude on). Unless --no-jail, java.io sees only ROOT, read-only,
 * as "/". Prints the tree or the error, and the parse time of the first (cold) run in microseconds.
 */
public final class XIncludeMain {
    public static void main(String[] args) throws Exception {
        boolean jail = true, probe = false;
        int bench = 0, i = 0;
        for (; i < args.length && args[i].startsWith("--"); i++) {
            switch (args[i]) {
                case "--no-jail": jail = false; break;
                case "--probe": probe = true; break;
                case "--bench": bench = Integer.parseInt(args[++i]); break;
                default: throw new IllegalArgumentException("unknown option " + args[i]);
            }
        }
        String root = args[i++];
        java.net.URL.setURLStreamHandlerFactory(new FileUrlHandlers());
        if (jail) VirtualFileSystemProvider.setInstance(new JailFileSystem(new CFileSystem(), root));
        if (probe) probe();
        int failures = 0;
        for (; i < args.length; i++) {
            System.out.println("== " + args[i]);
            long t0 = System.nanoTime();
            String result;
            try {
                result = "OK " + parse(args[i]);
            } catch (Exception e) {
                failures++;
                result = "FAILED " + e.getClass().getName() + ": " + e.getMessage();
            }
            long cold = (System.nanoTime() - t0) / 1000;
            System.out.println("   " + result);
            System.out.println("   cold parse: " + cold + " us");
            if (bench > 0) {
                long[] t = new long[bench];
                for (int k = 0; k < bench; k++) {
                    long s = System.nanoTime();
                    try { parse(args[i]); } catch (Exception e) { /* timed as well */ }
                    t[k] = System.nanoTime() - s;
                }
                java.util.Arrays.sort(t);
                System.out.println("   warm parse x" + bench + ": median " + t[bench / 2] / 1000 + " us, p95 "
                        + t[(int) Math.ceil(bench * 0.95) - 1] / 1000 + " us, min " + t[0] / 1000 + " us");
            }
        }
        System.out.println("failures: " + failures);
    }

    private static String parse(String systemId) throws Exception {
        XIncludeAwareParserConfiguration config = new XIncludeAwareParserConfiguration();
        DOMParser parser = new DOMParser(config);
        parser.setFeature("http://apache.org/xml/features/xinclude", true);
        parser.setFeature("http://apache.org/xml/features/xinclude/fixup-base-uris", false);
        parser.setErrorHandler(new ErrorHandler() {
            @Override public void warning(SAXParseException e) { System.out.println("   warning: " + e.getMessage()); }
            @Override public void error(SAXParseException e) throws SAXParseException { throw e; }
            @Override public void fatalError(SAXParseException e) throws SAXParseException { throw e; }
        });
        parser.parse(systemId);
        StringBuilder out = new StringBuilder();
        serialize(parser.getDocument().getDocumentElement(), out);
        return out.toString();
    }

    private static void probe() {
        System.out.println("== java.io probe");
        String[] list = new File("/").list();
        java.util.Arrays.sort(list);
        System.out.println("   list(/): " + String.join(" ", list));
        for (String path : new String[] {"/main.xml", "/etc/passwd", "/../etc/passwd", "/link-to-etc/passwd"}) {
            try (FileInputStream in = new FileInputStream(path)) {
                int n = 0;
                while (in.read() >= 0) n++;
                System.out.println("   read " + path + ": " + n + " bytes");
            } catch (IOException e) {
                System.out.println("   read " + path + ": " + e.getClass().getSimpleName());
            }
        }
    }

    private static void serialize(Node node, StringBuilder out) {
        switch (node.getNodeType()) {
            case Node.ELEMENT_NODE:
                out.append('<').append(node.getNodeName());
                NamedNodeMap attrs = node.getAttributes();
                for (int i = 0; i < attrs.getLength(); i++) {
                    Node a = attrs.item(i);
                    out.append(' ').append(a.getNodeName()).append("=\"").append(a.getNodeValue()).append('"');
                }
                out.append('>');
                for (Node c = node.getFirstChild(); c != null; c = c.getNextSibling()) serialize(c, out);
                out.append("</").append(node.getNodeName()).append('>');
                break;
            case Node.TEXT_NODE:
                // TeaVM's C console is not UTF-8 transparent, so show non-ASCII as escapes
                for (char ch : node.getNodeValue().trim().toCharArray()) {
                    if (ch < 128) out.append(ch); else out.append(String.format("\\u%04x", (int) ch));
                }
                break;
            default: break;
        }
    }

    private XIncludeMain() { }
}
