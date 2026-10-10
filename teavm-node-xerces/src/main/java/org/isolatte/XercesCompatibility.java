package org.isolatte;

import org.teavm.model.ClassHolder;
import org.teavm.model.ClassHolderTransformer;
import org.teavm.model.ClassHolderTransformerContext;
import org.teavm.model.MethodReference;
import org.teavm.model.instructions.InvokeInstruction;

/** Preserve Xerces' exception implementation while using TeaVM's IOException. */
public final class XercesCompatibility implements ClassHolderTransformer {
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
                        if (invoke.getMethod().getClassName().equals("java.io.CharConversionException")) {
                            invoke.setMethod(new MethodReference("java.io.IOException", invoke.getMethod().getDescriptor()));
                        }
                    }
                }
            }
        }
    }
}
