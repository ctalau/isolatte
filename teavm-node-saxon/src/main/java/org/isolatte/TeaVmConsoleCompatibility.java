package org.isolatte;

import org.teavm.model.ClassHolder;
import org.teavm.model.ClassHolderTransformer;
import org.teavm.model.ClassHolderTransformerContext;
import org.teavm.model.MethodDescriptor;
import org.teavm.model.ValueType;
import org.teavm.model.emit.ProgramEmitter;

/** TeaVM 0.16.0 clears flushAction before calling it; preserve it in a local. */
public final class TeaVmConsoleCompatibility implements ClassHolderTransformer {
    public void transformClass(ClassHolder cls, ClassHolderTransformerContext context) {
        if (!cls.getName().equals("org.teavm.classlib.impl.console.JsConsolePrintStream")) return;
        var method = cls.getMethod(new MethodDescriptor("flush", void.class));
        var emitter = ProgramEmitter.create(method, context.getHierarchy());
        var self = emitter.var(0, ValueType.object(cls.getName()));
        var action = self.getField("flushAction", Runnable.class);
        emitter.when(action.isNotNull()).thenDo(() -> {
            self.setField("flushAction", emitter.constantNull(Runnable.class));
            action.invokeVirtual("run", void.class);
        });
        emitter.exit();
    }
}
