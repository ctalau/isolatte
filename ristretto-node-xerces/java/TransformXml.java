import java.io.FileInputStream;
import java.io.StringWriter;
import javax.xml.transform.ErrorListener;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import net.sf.saxon.TransformerFactoryImpl;
import net.sf.saxon.lib.FeatureKeys;
import net.sf.saxon.trans.XPathException;
import org.apache.xerces.parsers.SAXParser;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

public final class TransformXml {
    private static SAXSource source(FileInputStream stream, String path) throws Exception {
        SAXParser parser = new SAXParser();
        parser.setFeature("http://xml.org/sax/features/namespaces", true);
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false);
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        parser.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        parser.setErrorHandler(new DefaultHandler() {
            public void error(SAXParseException error) throws SAXParseException { throw error; }
            public void fatalError(SAXParseException error) throws SAXParseException { throw error; }
        });
        InputSource input = new InputSource(stream);
        input.setSystemId("file:" + path);
        return new SAXSource(parser, input);
    }

    public static String transform(String xmlPath, String xsltPath) throws Exception {
        // Instantiate Saxon explicitly rather than relying on JAXP service discovery.
        TransformerFactoryImpl factory = new TransformerFactoryImpl();
        factory.setAttribute(FeatureKeys.ALLOW_EXTERNAL_FUNCTIONS, Boolean.FALSE);
        factory.getConfiguration().setUnparsedTextURIResolver((uri, encoding, configuration) -> {
            throw new XPathException("Additional XSLT resources are disabled: " + uri);
        });
        factory.setURIResolver((href, base) -> {
            throw new TransformerException("Additional XSLT resources are disabled: " + href);
        });
        factory.setErrorListener(new ErrorListener() {
            public void warning(TransformerException error) { }
            public void error(TransformerException error) throws TransformerException { throw error; }
            public void fatalError(TransformerException error) throws TransformerException { throw error; }
        });
        try (FileInputStream xml = new FileInputStream(xmlPath);
             FileInputStream xslt = new FileInputStream(xsltPath)) {
            Transformer transformer = factory.newTransformer(source(xslt, xsltPath));
            StringWriter output = new StringWriter();
            transformer.transform(source(xml, xmlPath), new StreamResult(output));
            return output.toString();
        }
    }
}
