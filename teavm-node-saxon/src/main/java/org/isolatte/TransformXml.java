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
        Processor processor = processor();
        return execute(processor, processor.newXsltCompiler().compile(source(stylesheet)), xml);
    }

    private static Processor processor() {
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
        return processor;
    }

    private static String execute(Processor processor, net.sf.saxon.s9api.XsltExecutable executable, String xml) throws Exception {
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

    @org.teavm.jso.JSExport
    public static String benchmark(String stylesheet, String xml, int warmup, int iterations, boolean reuse) throws Exception {
        Processor processor = reuse ? processor() : null;
        var executable = reuse ? processor.newXsltCompiler().compile(source(stylesheet)) : null;
        long[] timings = new long[iterations];
        String output = null;
        long start = System.nanoTime();
        for (int i = -warmup; i < iterations; i++) {
            long before = System.nanoTime();
            output = reuse ? execute(processor, executable, xml) : transform(stylesheet, xml);
            long duration = System.nanoTime() - before;
            if (i >= 0) timings[i] = duration;
        }
        long total = System.nanoTime() - start;
        java.util.Arrays.sort(timings);
        long sum = 0;
        for (long timing : timings) sum += timing;
        return "{\"medianMs\":" + timings[iterations / 2] / 1e6
            + ",\"p95Ms\":" + timings[(int) Math.ceil(iterations * 0.95) - 1] / 1e6
            + ",\"meanMs\":" + sum / 1e6 / iterations + ",\"totalMs\":" + total / 1e6
            + ",\"iterations\":" + iterations + ",\"warmup\":" + warmup
            + ",\"outputLength\":" + output.length() + ",\"outputHash\":" + output.hashCode() + "}";
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
