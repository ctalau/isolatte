package org.isolatte.c;

/** Direct replacements for Xerces' ObjectFactory reflection, for the classes Xerces asks for by name. */
public final class Shims {
    public static Object newInstance(String name, ClassLoader loader, boolean doFallback) {
        switch (name) {
            case "org.apache.xerces.impl.dv.dtd.DTDDVFactoryImpl": return new org.apache.xerces.impl.dv.dtd.DTDDVFactoryImpl();
            case "org.apache.xerces.impl.dv.dtd.XML11DTDDVFactoryImpl": return new org.apache.xerces.impl.dv.dtd.XML11DTDDVFactoryImpl();
            case "org.apache.xerces.parsers.XIncludeParserConfiguration": return new org.apache.xerces.parsers.XIncludeParserConfiguration();
            case "org.apache.xerces.parsers.XPointerParserConfiguration": return new org.apache.xerces.parsers.XPointerParserConfiguration();
            default: throw new IllegalStateException("no direct constructor for " + name);
        }
    }

    public static Class<?> findProviderClass(String name, ClassLoader loader, boolean doFallback) throws ClassNotFoundException {
        switch (name) {
            case "org.apache.xerces.dom.DocumentImpl": return org.apache.xerces.dom.DocumentImpl.class;
            case "org.apache.xerces.dom.CoreDocumentImpl": return org.apache.xerces.dom.CoreDocumentImpl.class;
            case "org.apache.xerces.dom.PSVIDocumentImpl": return org.apache.xerces.dom.PSVIDocumentImpl.class;
            default: throw new ClassNotFoundException(name);
        }
    }

    /** Only the XML Schema validator asks for a SAX reader by name; schema validation is not supported. */
    public static org.xml.sax.XMLReader createXMLReader() throws org.xml.sax.SAXException {
        throw new org.xml.sax.SAXException("XML Schema loading is not supported in this build");
    }

    private Shims() { }
}
