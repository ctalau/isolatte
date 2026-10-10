package org.isolatte;

import org.teavm.model.*;
import org.teavm.model.emit.ProgramEmitter;
import org.teavm.parsing.ClassRefsRenamer;

/** Explicit platform restrictions for the Node-only, in-memory experiment. */
public final class SaxonCompatibility implements ClassHolderTransformer {
    @Override
    public void transformClass(ClassHolder cls, ClassHolderTransformerContext context) {
        if (!cls.getName().startsWith("net.sf.saxon.")) return;
        new ClassRefsRenamer(new ReferenceCache(), name -> {
            switch (name) {
                case "java.util.concurrent.ConcurrentLinkedQueue": return "org.isolatte.ParserQueue";
                case "net.sf.saxon.lib.DigestMaker": return "org.isolatte.NodeDigest";
                case "java.text.Normalizer": return "org.isolatte.NodeNormalizer";
                case "java.text.Normalizer$Form": return "org.isolatte.NodeNormalizer$Form";
                case "java.io.LineNumberReader": return "org.isolatte.TextLinesReader";
                case "java.util.SimpleTimeZone": return "org.isolatte.FixedTimeZone";
                default: return name;
            }
        }).rename(cls);
        for (MethodHolder method : cls.getMethods()) {
            String owner = cls.getName();
            String name = method.getName();
            if (owner.equals("net.sf.saxon.lib.CatalogResourceResolver")) {
                if (name.equals("<init>")) {
                    var emitter = ProgramEmitter.create(method, context.getHierarchy());
                    emitter.var(0, ValueType.object(owner)).invokeSpecial("java.lang.Object", "<init>", ValueType.VOID);
                    emitter.exit();
                } else if (!name.equals("<clinit>")) {
                    unsupported(method, context);
                }
            } else if (owner.equals("net.sf.saxon.java.JavaPlatform")) {
                if (name.equals("locateResource")) {
                    var emitter = ProgramEmitter.create(method, context.getHierarchy());
                    emitter.invoke("org.isolatte.SaxonResources", "open", ValueType.object("java.io.InputStream"),
                        emitter.var(1, String.class)).returnValue();
                } else if (name.equals("loadParser") || name.equals("loadParserForXmlFragments")) {
                    var emitter = ProgramEmitter.create(method, context.getHierarchy());
                    emitter.invoke("org.isolatte.TransformXml", "newReader", ValueType.object("org.xml.sax.XMLReader")).returnValue();
                } else if (name.equals("makeCollation") || name.equals("makeUcaCollator") || name.equals("getCollationKey")) {
                    unsupported(method, context);
                }
            } else if ((owner.equals("net.sf.saxon.Configuration") &&
                       ((name.equals("makeTraceListener") && method.parameterCount() > 0) || name.equals("instantiateConfiguration"))) ||
                       (owner.equals("net.sf.saxon.trans.DynamicLoader") && name.equals("getClass"))) {
                unsupported(method, context);
            } else if (owner.equals("net.sf.saxon.Configuration") && name.equals("newConfiguration")) {
                var emitter = ProgramEmitter.create(method, context.getHierarchy());
                emitter.construct("net.sf.saxon.Configuration").returnValue();
            } else if ((owner.equals("net.sf.saxon.dom.DOMObjectModel") && name.equals("getDocumentBuilder")) ||
                       (owner.equals("net.sf.saxon.resource.StandardCollectionFinder") && name.equals("findCollection")) ||
                       (owner.equals("net.sf.saxon.resource.UnknownResource") && name.equals("getItem")) ||
                       (owner.equals("net.sf.saxon.resource.BinaryResource") && name.equals("readBinaryFromConn"))) {
                unsupported(method, context);
            } else if (owner.equals("net.sf.saxon.lib.StandardEnvironmentVariableResolver") &&
                       (name.equals("getAvailableEnvironmentVariables") || name.equals("getEnvironmentVariable"))) {
                var emitter = ProgramEmitter.create(method, context.getHierarchy());
                if (name.equals("getAvailableEnvironmentVariables")) {
                    emitter.invoke("java.util.Collections", "emptySet", ValueType.object("java.util.Set")).returnValue();
                } else if (name.equals("getEnvironmentVariable")) {
                    emitter.constantNull(String.class).returnValue();
                }
            }
        }
    }

    private static void unsupported(MethodHolder method, ClassHolderTransformerContext context) {
        ProgramEmitter emitter = ProgramEmitter.create(method, context.getHierarchy());
        emitter.construct(UnsupportedOperationException.class,
            emitter.constant("Unavailable in TeaVM experiment: " + method.getReference())).raise();
    }
}
