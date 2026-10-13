package org.isolatte.demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.parsers.XIncludeAwareParserConfiguration;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXParseException;

/**
 * Parses each argument (a system ID) with Xerces, XInclude processing on, and prints the resulting
 * tree or the error. Plain application code: it uses java.io and Xerces only, and knows nothing about
 * the file system behind java.io.
 *
 * <p>{@code --probe} first prints a few direct java.io observations.
 */
public final class XIncludeDemo {
    public static void main(String[] args) throws Exception {
        int failures = 0;
        for (String arg : args) {
            if (arg.equals("--probe")) {
                probe();
                continue;
            }
            System.out.println("== " + arg);
            try {
                DOMParser parser = new DOMParser(new XIncludeAwareParserConfiguration());
                parser.setFeature("http://apache.org/xml/features/xinclude", true);
                parser.setFeature("http://apache.org/xml/features/xinclude/fixup-base-uris", false);
                parser.setErrorHandler(new ErrorHandler() {
                    @Override
                    public void warning(SAXParseException e) {
                        System.out.println("   warning: " + e.getMessage());
                    }

                    @Override
                    public void error(SAXParseException e) throws SAXParseException {
                        throw e;
                    }

                    @Override
                    public void fatalError(SAXParseException e) throws SAXParseException {
                        throw e;
                    }
                });
                parser.parse(arg);
                Document doc = parser.getDocument();
                StringBuilder out = new StringBuilder();
                serialize(doc.getDocumentElement(), out);
                System.out.println("   OK " + out);
            } catch (Exception e) {
                failures++;
                System.out.println("   FAILED " + e.getClass().getName() + ": " + e.getMessage());
            }
        }
        System.out.println("failures: " + failures);
    }

    private static void probe() {
        System.out.println("== java.io probe");
        File root = new File("/");
        System.out.println("   File.class source: " + sourceOf());
        System.out.println("   user.dir property: " + System.getProperty("user.dir")
                + ", new File(\"\").getAbsolutePath(): " + new File("").getAbsolutePath());
        String[] list = root.list();
        java.util.Arrays.sort(list);
        System.out.println("   new File(\"/\").list(): " + String.join(" ", list));
        try {
            System.out.println("   new File(\"/../..\").getCanonicalPath(): " + new File("/../..").getCanonicalPath());
        } catch (IOException e) {
            System.out.println("   canonical path failed: " + e);
        }
        for (String path : new String[] {"/main.xml", "/etc/passwd", "/../outside/secret.xml"}) {
            try (FileInputStream in = new FileInputStream(path)) {
                System.out.println("   read " + path + ": " + in.readAllBytes().length + " bytes");
            } catch (IOException e) {
                System.out.println("   read " + path + ": " + e.getClass().getSimpleName());
            }
        }
        try {
            new File("/main.xml").toPath();
        } catch (UnsupportedOperationException e) {
            System.out.println("   File.toPath(): UnsupportedOperationException");
        }
        // Not jailed: OpenJDK's java.nio.file and process launching are not part of the overlay.
        System.out.println("   NIO Files.isReadable(/etc/passwd): "
                + java.nio.file.Files.isReadable(java.nio.file.Path.of("/etc/passwd")));
        try {
            System.out.println("   ProcessBuilder(\"true\") exit: " + new ProcessBuilder("true").start().waitFor());
        } catch (IOException | InterruptedException e) {
            System.out.println("   ProcessBuilder: " + e);
        }
    }

    /** The SourceFile attribute of java.io.File, as seen in a stack frame: TFile.java for TeaVM. */
    private static String sourceOf() {
        try {
            new File((String) null);
        } catch (NullPointerException e) {
            for (StackTraceElement f : e.getStackTrace()) {
                if (f.getClassName().equals("java.io.File")) {
                    return f.getFileName();
                }
            }
        }
        return "?";
    }

    private static void serialize(Node node, StringBuilder out) {
        switch (node.getNodeType()) {
            case Node.ELEMENT_NODE -> {
                out.append('<').append(node.getNodeName());
                NamedNodeMap attrs = node.getAttributes();
                for (int i = 0; i < attrs.getLength(); i++) {
                    Node a = attrs.item(i);
                    out.append(' ').append(a.getNodeName()).append("=\"").append(a.getNodeValue()).append('"');
                }
                out.append('>');
                for (Node c = node.getFirstChild(); c != null; c = c.getNextSibling()) {
                    serialize(c, out);
                }
                out.append("</").append(node.getNodeName()).append('>');
            }
            case Node.TEXT_NODE -> out.append(node.getNodeValue().strip());
            default -> {
            }
        }
    }

    private XIncludeDemo() {
    }
}
