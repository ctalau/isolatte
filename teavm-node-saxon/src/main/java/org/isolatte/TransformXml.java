package org.isolatte;

import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.transform.sax.SAXSource;
import net.sf.saxon.s9api.Processor;
import net.sf.saxon.s9api.Serializer;
import org.apache.xerces.parsers.NonValidatingConfiguration;
import org.apache.xerces.parsers.SAXParser;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

public final class TransformXml {
    public static void main(String[] args) throws Exception {
        System.out.print(transform(args[0], args[1]));
    }

    @org.teavm.jso.JSExport
    public static String transform(String stylesheet, String xml) throws Exception {
        // Xerces also parses embedded Saxon tables with no document base URI.
        if (System.getProperty("user.dir") == null) System.setProperty("user.dir", "/");
        Processor processor = new Processor(new net.sf.saxon.Configuration());
        processor.getUnderlyingConfiguration().setResourceResolver(request -> {
            throw new net.sf.saxon.trans.XPathException("External resource access denied: " + request.uri);
        });
        processor.getUnderlyingConfiguration().setUnparsedTextURIResolver((uri, encoding, config) -> {
            throw new net.sf.saxon.trans.XPathException("External text access denied: " + uri);
        });
        processor.getUnderlyingConfiguration().setCollectionFinder((context, uri) -> {
            throw new net.sf.saxon.trans.XPathException("External collection access denied: " + uri);
        });
        var executable = processor.newXsltCompiler().compile(source(stylesheet));
        var transformer = executable.load();
        transformer.setSource(source(xml));
        transformer.setResultDocumentHandler(uri -> {
            throw new UnsupportedOperationException("Secondary result documents denied: " + uri);
        });
        StringWriter output = new StringWriter();
        Serializer serializer = processor.newSerializer(output);
        transformer.setDestination(serializer);
        transformer.transform();
        return output.toString();
    }

    public static org.xml.sax.XMLReader newReader() throws Exception {
        NonValidatingConfiguration configuration = new NonValidatingConfiguration() {
            { configurePipeline(); }
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
        parser.setErrorHandler(new DefaultHandler() {
            public void error(SAXParseException e) throws SAXParseException { throw e; }
            public void fatalError(SAXParseException e) throws SAXParseException { throw e; }
        });
        return parser;
    }

    private static SAXSource source(String xml) throws Exception {
        InputSource input = new InputSource(new StringReader(xml));
        input.setSystemId("urn:isolatte:input");
        return new SAXSource(newReader(), input);
    }
}
