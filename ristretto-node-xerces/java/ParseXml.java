import java.io.FileInputStream;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.impl.Version;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

public final class ParseXml {
    public static String parse(String path) throws Exception {
        DOMParser parser = new DOMParser();
        parser.setFeature("http://xml.org/sax/features/namespaces", true);
        // Input XML cannot cause the parser to read additional files or URLs.
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        parser.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        parser.setErrorHandler(new DefaultHandler() {
            public void error(SAXParseException error) throws SAXParseException { throw error; }
            public void fatalError(SAXParseException error) throws SAXParseException { throw error; }
        });
        try (FileInputStream stream = new FileInputStream(path)) {
            parser.parse(new InputSource(stream));
        }
        Document document = parser.getDocument();
        Element root = document.getDocumentElement();
        return "{\"parser\":" + quote(parser.getClass().getName())
            + ",\"xercesVersion\":" + quote(Version.getVersion())
            + ",\"javaVersion\":" + quote(System.getProperty("java.version"))
            + ",\"root\":" + quote(root.getTagName())
            + ",\"namespace\":" + quote(root.getNamespaceURI())
            + ",\"elementCount\":" + document.getElementsByTagName("*").getLength()
            + ",\"text\":" + quote(root.getTextContent().trim()) + "}";
    }

    private static String quote(String value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 32) {
                        result.append(String.format("\\u%04x", (int) c));
                    } else result.append(c);
            }
        }
        return result.append('"').toString();
    }
}
