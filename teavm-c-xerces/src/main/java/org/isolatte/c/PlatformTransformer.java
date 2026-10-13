package org.isolatte.c;

import org.teavm.model.ClassHolder;
import org.teavm.model.ClassHolderTransformer;
import org.teavm.model.ClassHolderTransformerContext;
import org.teavm.model.MethodDescriptor;
import org.teavm.model.MethodHolder;
import org.teavm.model.emit.ProgramEmitter;

/**
 * Two platform adjustments for the C backend. TeaVM's http(s) handler is built on JavaScript
 * XMLHttpRequest and does not compile for C: make it refuse. And System's static initializer asks libc for
 * the home directory (getpwuid reads /etc/nsswitch.conf and /etc/passwd before main): answer "/" instead.
 */
public final class PlatformTransformer implements ClassHolderTransformer {
    @Override
    public void transformClass(ClassHolder cls, ClassHolderTransformerContext context) {
        boolean xhr = cls.getName().equals("java.net.impl.XHRStreamHandler");
        boolean system = cls.getName().equals("java.lang.System");
        if (!xhr && !system) return;
        for (MethodHolder method : cls.getMethods()) {
            if (system && method.getName().equals("getHomeDir")) {
                ProgramEmitter.create(method, context.getHierarchy()).constant("/").returnValue();
            } else if (xhr && method.getName().equals("openConnection")) {
                ProgramEmitter pe = ProgramEmitter.create(method, context.getHierarchy());
                pe.construct(java.io.IOException.class, pe.constant("http is not available in the C backend")).raise();
            }
        }
    }
}
