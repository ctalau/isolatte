package org.isolatte.c;

import org.teavm.model.ClassHolder;
import org.teavm.model.ClassHolderTransformer;
import org.teavm.model.ClassHolderTransformerContext;
import org.teavm.model.MethodReference;
import org.teavm.model.instructions.InvokeInstruction;

/** Preserve Xerces' exception implementation while using TeaVM's IOException. */
public final class XercesCompat implements ClassHolderTransformer {
    @Override
    public void transformClass(ClassHolder cls, ClassHolderTransformerContext context) {
        if (!cls.getName().startsWith("org.apache.xerces.")) return;
        if (cls.getName().equals("org.apache.xerces.impl.io.MalformedByteSequenceException")) {
            cls.setParent("java.io.IOException");
        }
        for (var method : cls.getMethods()) {
            if (method.getProgram() == null) continue;
            for (int i = 0; i < method.getProgram().basicBlockCount(); i++) {
                for (var handler : method.getProgram().basicBlockAt(i).getTryCatchBlocks()) {
                    if ("java.io.CharConversionException".equals(handler.getExceptionType())) {
                        handler.setExceptionType("org.apache.xerces.impl.io.MalformedByteSequenceException");
                    }
                }
                for (var instruction : method.getProgram().basicBlockAt(i)) {
                    if (instruction instanceof InvokeInstruction) {
                        var invoke = (InvokeInstruction) instruction;
                        String owner = invoke.getMethod().getClassName();
                        String name = invoke.getMethod().getName();
                        if (owner.startsWith("org.apache.xerces.") && owner.endsWith(".ObjectFactory")
                                && (name.equals("newInstance") || name.equals("findProviderClass"))) {
                            invoke.setMethod(new MethodReference("org.isolatte.c.Shims", invoke.getMethod().getDescriptor()));
                            continue;
                        }
                        if (owner.equals("org.xml.sax.helpers.XMLReaderFactory") && name.equals("createXMLReader")) {
                            invoke.setMethod(new MethodReference("org.isolatte.c.Shims", invoke.getMethod().getDescriptor()));
                            continue;
                        }
                        if (invoke.getMethod().getClassName().equals("java.io.CharConversionException")) {
                            invoke.setMethod(new MethodReference("java.io.IOException", invoke.getMethod().getDescriptor()));
                        }
                    }
                }
            }
        }
    }
}
