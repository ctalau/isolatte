package org.isolatte;

import java.io.StringReader;
import org.apache.xerces.parsers.SAXParser;
import org.apache.xerces.parsers.NonValidatingConfiguration;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

public final class ParseXml {
    public static void main(String[] args) throws Exception {
        NonValidatingConfiguration configuration = new NonValidatingConfiguration() {
            {
                // Register scanner defaults before applying our feature values.
                configurePipeline();
            }
            @Override
            protected org.apache.xerces.impl.dv.DTDDVFactory createDatatypeValidatorFactory() {
                return new org.apache.xerces.impl.dv.dtd.DTDDVFactoryImpl();
            }
        };
        SAXParser parser = new SAXParser(configuration);
        parser.setFeature("http://xml.org/sax/features/namespaces", true);
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        parser.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        Handler handler = new Handler();
        parser.setContentHandler(handler);
        parser.setErrorHandler(handler);
        parser.parse(new InputSource(new StringReader(args[0])));
        System.out.println("{\"parser\":\"org.apache.xerces.parsers.SAXParser\",\"xercesVersion\":\""
            + org.apache.xerces.impl.Version.getVersion() + "\",\"root\":" + quote(handler.root)
            + ",\"namespace\":" + quote(handler.namespace) + ",\"elementCount\":" + handler.elements
            + ",\"text\":" + quote(handler.text.toString().trim()) + "}");
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') result.append('\\').append(c);
            else if (c < 32) {
                result.append("\\u00").append("0123456789abcdef".charAt(c >> 4))
                    .append("0123456789abcdef".charAt(c & 15));
            } else result.append(c);
        }
        return result.append('"').toString();
    }

    private static final class Handler extends DefaultHandler {
        String root;
        String namespace;
        int elements;
        final StringBuilder text = new StringBuilder();
        public void startElement(String uri, String local, String name, org.xml.sax.Attributes attributes) {
            if (elements++ == 0) { root = name; namespace = uri; }
        }
        public void characters(char[] chars, int start, int length) { text.append(chars, start, length); }
        public void error(SAXParseException error) throws SAXParseException { throw error; }
        public void fatalError(SAXParseException error) throws SAXParseException { throw error; }
    }
}
