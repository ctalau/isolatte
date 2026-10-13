package org.isolatte.vm;

import java.util.List;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;

/** A guest method: bytecode prepared for the interpreter, or a host {@link Native}. */
final class VMethod {
    final VClass owner;
    final String name;
    final String desc;
    final int access;
    final MethodNode node;
    final Type[] argTypes;
    final Type returnType;
    Native nat;

    // Prepared lazily on first execution.
    AbstractInsnNode[] code;
    int[] lines;
    /** Per-instruction link cache: resolved fields, methods, classes, jump tables, call sites. */
    Object[] links;
    int[] tryStart;
    int[] tryEnd;
    int[] tryHandler;
    String[] tryType;
    VClass[] tryClass;

    VMethod(VClass owner, String name, String desc, int access, MethodNode node) {
        this.owner = owner;
        this.name = name;
        this.desc = desc;
        this.access = access;
        this.node = node;
        this.argTypes = Type.getArgumentTypes(desc);
        this.returnType = Type.getReturnType(desc);
    }

    boolean isStatic() {
        return (access & Opcodes.ACC_STATIC) != 0;
    }

    boolean isAbstract() {
        return (access & Opcodes.ACC_ABSTRACT) != 0;
    }

    boolean isNative() {
        return (access & Opcodes.ACC_NATIVE) != 0;
    }

    void prepare() {
        if (code != null) {
            return;
        }
        AbstractInsnNode[] insns = node.instructions.toArray();
        int[] ln = new int[insns.length];
        int line = -1;
        for (int i = 0; i < insns.length; i++) {
            if (insns[i] instanceof LineNumberNode l) {
                line = l.line;
            }
            ln[i] = line;
        }
        List<TryCatchBlockNode> tcbs = node.tryCatchBlocks;
        int n = tcbs.size();
        tryStart = new int[n];
        tryEnd = new int[n];
        tryHandler = new int[n];
        tryType = new String[n];
        tryClass = new VClass[n];
        for (int i = 0; i < n; i++) {
            TryCatchBlockNode t = tcbs.get(i);
            tryStart[i] = node.instructions.indexOf(t.start);
            tryEnd[i] = node.instructions.indexOf(t.end);
            tryHandler[i] = node.instructions.indexOf(t.handler);
            tryType[i] = t.type;
        }
        lines = ln;
        links = new Object[insns.length];
        code = insns;
    }

    String key() {
        return owner.name + "." + name + desc;
    }

    @Override
    public String toString() {
        return key();
    }
}
