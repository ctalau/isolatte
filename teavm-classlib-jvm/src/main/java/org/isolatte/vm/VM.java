package org.isolatte.vm;

import static org.objectweb.asm.Opcodes.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * A small JVM: a bytecode interpreter running on a host JVM, with no class library of its own. Every
 * guest class, {@code java.lang.Object} included, is loaded from the guest class path through
 * {@link Loader}; the VM's only contract with the class library is the set of {@link Native}s
 * registered by {@link Intrinsics}. A guest reaches the host exclusively through those natives.
 *
 * <p>Single-threaded; monitors are no-ops. Values: int-like types are Integers, long/float/double
 * are boxed, references are {@link VObject}, {@link RefArray}, host primitive arrays or null. Each
 * operand stack entry and local holds one value (long/double take one stack entry, but keep JVM
 * local numbering), so dup2/pop2 and friends decide by the runtime type of the top value.
 */
final class VM {
    final Loader loader;
    final Map<String, VClass> classes = new HashMap<>();
    final Map<String, Native> natives = new HashMap<>();
    /**
     * Methods the VM adds to guest classes that lack them (gaps in TeaVM's class library), keyed by
     * class name, then name + descriptor. They behave like declared public methods.
     */
    final Map<String, Map<String, Native>> additions = new HashMap<>();
    final Map<String, VObject> interned = new HashMap<>();
    final List<Frame> frames = new ArrayList<>();
    final Map<Character, VClass> primitives = new HashMap<>();
    final boolean trace = System.getenv("VM_TRACE") != null;
    final List<String> missing = new ArrayList<>();
    long instructions;
    int lambdaCount;

    VClass objectClass;
    VClass stringClass;
    VClass classInfoClass;
    VClass stringInfoClass;

    /** A guest frame, for stack traces. */
    static final class Frame {
        final VMethod method;
        int pc;

        Frame(VMethod method) {
            this.method = method;
        }
    }

    VM(Loader loader) {
        this.loader = loader;
        for (char c : "ZBCSIJFDV".toCharArray()) {
            primitives.put(c, new VClass(String.valueOf(c), null, ACC_PUBLIC | ACC_FINAL | ACC_ABSTRACT, null, c));
        }
    }

    void boot() {
        objectClass = load("java/lang/Object");
        stringClass = load("java/lang/String");
        classInfoClass = load("org/teavm/runtime/reflect/ClassInfo");
        stringInfoClass = load("org/teavm/runtime/StringInfo");
    }

    // ---------------------------------------------------------------- classes

    VClass primitive(char c) {
        return primitives.get(c);
    }

    /** Loads and links a class by internal name or array descriptor; null when it does not exist. */
    VClass tryLoad(String name) {
        VClass c = classes.get(name);
        if (c != null) {
            return c;
        }
        if (name.startsWith("[")) {
            VClass comp = typeOf(name.substring(1));
            return comp == null ? null : arrayOf(comp);
        }
        ClassNode node = loader.load(name);
        if (node == null) {
            return null;
        }
        try {
            return link(node);
        } catch (RuntimeException e) {
            classes.remove(name); // e.g. a missing superclass: the class does not exist either
            throw e;
        }
    }

    VClass load(String name) {
        VClass c = tryLoad(name);
        if (c == null) {
            if (trace || !missing.contains(name)) {
                missing.add(name);
            }
            throw error("java/lang/NoClassDefFoundError", name.replace('/', '.'));
        }
        return c;
    }

    /** A class from a field descriptor ({@code I}, {@code Lx/Y;}, {@code [I}). */
    VClass typeOf(String desc) {
        switch (desc.charAt(0)) {
            case 'L':
                return tryLoad(desc.substring(1, desc.length() - 1));
            case '[':
                return tryLoad(desc);
            default:
                return primitive(desc.charAt(0));
        }
    }

    VClass arrayOf(VClass comp) {
        if (comp.arrayClass == null) {
            String name = "[" + comp.descriptor();
            VClass a = new VClass(name, null, ACC_PUBLIC | ACC_FINAL | ACC_ABSTRACT, comp, (char) 0);
            a.superClass = objectClass;
            VClass cloneable = tryLoad("java/lang/Cloneable");
            VClass serializable = tryLoad("java/io/Serializable");
            List<VClass> ifaces = new ArrayList<>();
            if (cloneable != null) {
                ifaces.add(cloneable);
            }
            if (serializable != null) {
                ifaces.add(serializable);
            }
            a.interfaces = ifaces.toArray(new VClass[0]);
            a.state = VClass.INITIALIZED;
            classes.put(name, a);
            comp.arrayClass = a;
        }
        return comp.arrayClass;
    }

    private VClass link(ClassNode node) {
        VClass c = new VClass(node.name, node, node.access, null, (char) 0);
        classes.put(node.name, c);
        if (node.superName != null) {
            c.superClass = load(node.superName);
        }
        List<VClass> ifaces = new ArrayList<>();
        for (String i : node.interfaces) {
            ifaces.add(load(i));
        }
        c.interfaces = ifaces.toArray(new VClass[0]);

        int slot = c.superClass != null ? c.superClass.instanceSlots : 0;
        List<Object> defaults = new ArrayList<>();
        if (c.superClass != null) {
            defaults.addAll(java.util.Arrays.asList(c.superClass.instanceDefaults));
        }
        int staticSlot = 0;
        for (FieldNode f : node.fields) {
            boolean isStatic = (f.access & ACC_STATIC) != 0;
            VField vf = new VField(c, f.name, f.desc, f.access, isStatic ? staticSlot++ : slot++);
            if (!isStatic) {
                defaults.add(VField.defaultValue(f.desc));
            }
            c.fields.put(f.name, vf);
        }
        c.instanceSlots = slot;
        c.instanceDefaults = defaults.toArray();
        c.statics = new Object[staticSlot];
        for (FieldNode f : node.fields) {
            if ((f.access & ACC_STATIC) != 0) {
                VField vf = c.fields.get(f.name);
                Object v = f.value;
                if (v == null) {
                    v = VField.defaultValue(f.desc);
                } else if (v instanceof String s) {
                    v = intern(s);
                }
                c.statics[vf.slot] = v;
            }
        }
        for (MethodNode m : node.methods) {
            VMethod vm = new VMethod(c, m.name, m.desc, m.access, m);
            vm.nat = natives.get(vm.key());
            c.methods.put(m.name + m.desc, vm);
        }
        for (Map.Entry<String, Native> e : additions.getOrDefault(c.name, Map.of()).entrySet()) {
            if (!c.methods.containsKey(e.getKey())) {
                int paren = e.getKey().indexOf('(');
                VMethod added = new VMethod(c, e.getKey().substring(0, paren), e.getKey().substring(paren), ACC_PUBLIC, null);
                added.nat = e.getValue();
                c.methods.put(e.getKey(), added);
            }
        }
        return c;
    }

    void initialize(VClass c) {
        if (c.state != VClass.LOADED) {
            return;
        }
        c.state = VClass.INITIALIZING;
        if (c.superClass != null) {
            initialize(c.superClass);
        }
        VMethod clinit = c.methods.get("<clinit>()V");
        if (clinit != null) {
            try {
                invoke(clinit, new Object[0]);
            } catch (GuestException e) {
                if (trace) {
                    System.err.println("[vm] <clinit> of " + c.name + " threw " + describe(e.exception));
                }
                c.state = VClass.INITIALIZED;
                throw e;
            }
        }
        c.state = VClass.INITIALIZED;
    }

    VClass classOf(Object o) {
        if (o instanceof VObject v) {
            return v.cls;
        }
        if (o instanceof RefArray a) {
            return a.cls;
        }
        if (o instanceof int[]) {
            return arrayOf(primitive('I'));
        }
        if (o instanceof char[]) {
            return arrayOf(primitive('C'));
        }
        if (o instanceof byte[]) {
            return arrayOf(primitive('B'));
        }
        if (o instanceof boolean[]) {
            return arrayOf(primitive('Z'));
        }
        if (o instanceof long[]) {
            return arrayOf(primitive('J'));
        }
        if (o instanceof double[]) {
            return arrayOf(primitive('D'));
        }
        if (o instanceof float[]) {
            return arrayOf(primitive('F'));
        }
        if (o instanceof short[]) {
            return arrayOf(primitive('S'));
        }
        throw new IllegalStateException("not a guest value: " + o);
    }

    /** Declared field lookup per JVMS 5.4.3.2: class, superinterfaces, superclass. */
    VField findField(VClass c, String name) {
        for (VClass k = c; k != null; k = k.superClass) {
            VField f = k.fields.get(name);
            if (f != null) {
                return f;
            }
            for (VClass i : k.interfaces) {
                f = findField(i, name);
                if (f != null) {
                    return f;
                }
            }
        }
        return null;
    }

    /** Method lookup for invokestatic/invokespecial: the class, its superclasses, then interfaces. */
    VMethod findMethod(VClass c, String nameDesc) {
        for (VClass k = c; k != null; k = k.superClass) {
            VMethod m = k.methods.get(nameDesc);
            if (m != null) {
                return m;
            }
        }
        return findDefault(c, nameDesc, true);
    }

    private VMethod findDefault(VClass c, String nameDesc, boolean allowAbstract) {
        for (VClass k = c; k != null; k = k.superClass) {
            for (VClass i : k.interfaces) {
                VMethod m = i.methods.get(nameDesc);
                if (m != null && (allowAbstract || !m.isAbstract()) && !m.isStatic()) {
                    return m;
                }
                m = findDefault(i, nameDesc, allowAbstract);
                if (m != null) {
                    return m;
                }
            }
        }
        return null;
    }

    /** Virtual dispatch on the receiver's class. */
    VMethod virtualMethod(VClass c, String nameDesc) {
        VMethod m = c.virtualCache.get(nameDesc);
        if (m != null) {
            return m;
        }
        for (VClass k = c; k != null && m == null; k = k.superClass) {
            VMethod d = k.methods.get(nameDesc);
            if (d != null && !d.isStatic() && !d.isAbstract()) {
                m = d;
            }
        }
        if (m == null) {
            m = findDefault(c, nameDesc, false);
        }
        if (m == null && c.isArray()) {
            m = virtualMethod(objectClass, nameDesc);
        }
        if (m == null) {
            boolean declared = findMethod(c, nameDesc) != null;
            if (trace) {
                System.err.println("[vm] no implementation of " + c.name + "." + nameDesc);
            }
            throw error(declared ? "java/lang/AbstractMethodError" : "java/lang/NoSuchMethodError",
                    c.javaName() + "." + nameDesc);
        }
        c.virtualCache.put(nameDesc, m);
        return m;
    }

    /**
     * A VM-made class: Object's subclass implementing {@code ifaces}, whose methods are host
     * {@link Native}s (lambdas, metadata resources). Instances carry their state in {@code hidden}.
     */
    VClass synthetic(String name, List<VClass> ifaces, Map<String, Native> impls, String sourceFile) {
        VClass cls = new VClass(name, null, ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC, null, (char) 0);
        cls.superClass = objectClass;
        cls.interfaces = ifaces.toArray(new VClass[0]);
        cls.instanceSlots = objectClass.instanceSlots;
        cls.instanceDefaults = objectClass.instanceDefaults;
        cls.state = VClass.INITIALIZED;
        cls.sourceFile = sourceFile;
        for (Map.Entry<String, Native> e : impls.entrySet()) {
            int paren = e.getKey().indexOf('(');
            VMethod m = new VMethod(cls, e.getKey().substring(0, paren), e.getKey().substring(paren), ACC_PUBLIC, null);
            m.nat = e.getValue();
            cls.methods.put(e.getKey(), m);
        }
        classes.put(name, cls);
        return cls;
    }

    // ---------------------------------------------------------------- objects

    VObject newObject(VClass c) {
        initialize(c);
        return new VObject(c);
    }

    /** Creates a guest object and runs the constructor with the given descriptor. */
    VObject construct(String className, String desc, Object... args) {
        VClass c = load(className);
        VObject o = newObject(c);
        Object[] full = new Object[args.length + 1];
        full[0] = o;
        System.arraycopy(args, 0, full, 1, args.length);
        VMethod init = c.methods.get("<init>" + desc);
        if (init == null) {
            throw new IllegalStateException("no constructor " + className + desc);
        }
        invoke(init, full);
        return o;
    }

    /** A guest exception to throw, e.g. {@code throw vm.error("java/lang/NullPointerException", null)}. */
    GuestException error(String className, String message) {
        VClass c = tryLoad(className);
        if (c == null) {
            // TeaVM's class library lacks some error classes (e.g. UnsatisfiedLinkError).
            message = className.replace('/', '.') + (message != null ? ": " + message : "");
            className = className.endsWith("Error") ? "java/lang/Error" : "java/lang/RuntimeException";
            c = load(className);
        }
        VObject e = message == null ? construct(className, "()V") : construct(className, "(Ljava/lang/String;)V", str(message));
        return new GuestException(e);
    }

    VObject str(String s) {
        if (s == null) {
            return null;
        }
        VObject o = new VObject(stringClass);
        o.hidden = s;
        return o;
    }

    VObject intern(String s) {
        VObject o = interned.get(s);
        if (o == null) {
            o = str(s);
            interned.put(s, o);
        }
        return o;
    }

    static String host(Object guestString) {
        return guestString == null ? null : (String) ((VObject) guestString).hidden;
    }

    VObject classInfo(VClass c) {
        if (c.classInfo == null) {
            VObject info = new VObject(classInfoClass);
            info.hidden = c;
            c.classInfo = info;
        }
        return c.classInfo;
    }

    VObject classObject(VClass c) {
        if (c.classObject == null) {
            VClass cls = load("java/lang/Class");
            c.classObject = (VObject) invoke(findMethod(cls, "createClass(Lorg/teavm/runtime/reflect/ClassInfo;)Ljava/lang/Class;"),
                    new Object[] {classInfo(c)});
        }
        return c.classObject;
    }

    /** Calls a guest static method by name, initializing its class. */
    Object callStatic(String className, String nameDesc, Object... args) {
        VClass c = load(className);
        initialize(c);
        VMethod m = findMethod(c, nameDesc);
        if (m == null) {
            throw new IllegalStateException("no method " + className + "." + nameDesc);
        }
        return invoke(m, args);
    }

    /** Calls a guest virtual method on {@code args[0]}. */
    Object callVirtual(String nameDesc, Object... args) {
        if (args[0] == null) {
            throw error("java/lang/NullPointerException", null);
        }
        return invoke(virtualMethod(classOf(args[0]), nameDesc), args);
    }

    String describe(VObject throwable) {
        try {
            return host(callVirtual("toString()Ljava/lang/String;", throwable));
        } catch (RuntimeException e) {
            return throwable.cls.javaName();
        }
    }

    // ---------------------------------------------------------------- invocation

    Object invoke(VMethod m, Object[] args) {
        if (m.nat != null) {
            return m.nat.call(args);
        }
        if (m.isNative()) {
            if (!missing.contains("native " + m.key())) {
                missing.add("native " + m.key());
            }
            if (trace) {
                System.err.println("[vm] unimplemented native " + m.key());
            }
            throw error("java/lang/UnsatisfiedLinkError", m.owner.javaName() + "." + m.name + m.desc);
        }
        if (m.isAbstract() || m.node.instructions.size() == 0) {
            throw error("java/lang/AbstractMethodError", m.owner.javaName() + "." + m.name + m.desc);
        }
        Object[] locals = new Object[Math.max(m.node.maxLocals, 1)];
        int slot = 0;
        int i = 0;
        if (!m.isStatic()) {
            locals[slot++] = args[i++];
        }
        for (Type t : m.argTypes) {
            locals[slot] = args[i++];
            slot += t.getSize();
        }
        Frame frame = new Frame(m);
        frames.add(frame);
        if (frames.size() > 3000) {
            frames.remove(frames.size() - 1);
            throw error("java/lang/StackOverflowError", null);
        }
        try {
            return execute(m, locals, frame);
        } finally {
            frames.remove(frames.size() - 1);
        }
    }

    private static boolean cat2(Object v) {
        return v instanceof Long || v instanceof Double;
    }

    private Object execute(VMethod m, Object[] locals, Frame frame) {
        m.prepare();
        final AbstractInsnNode[] code = m.code;
        final Object[] links = m.links;
        Object[] stack = new Object[m.node.maxStack + 2];
        int sp = 0;
        int pc = 0;
        while (true) {
            try {
                while (true) {
                    AbstractInsnNode insn = code[pc];
                    int op = insn.getOpcode();
                    if (op < 0) {
                        pc++;
                        continue;
                    }
                    frame.pc = pc;
                    instructions++;
                    switch (op) {
                        case NOP:
                            break;
                        case ACONST_NULL:
                            stack[sp++] = null;
                            break;
                        case ICONST_M1: case ICONST_0: case ICONST_1: case ICONST_2: case ICONST_3: case ICONST_4: case ICONST_5:
                            stack[sp++] = op - ICONST_0;
                            break;
                        case LCONST_0: case LCONST_1:
                            stack[sp++] = (long) (op - LCONST_0);
                            break;
                        case FCONST_0: case FCONST_1: case FCONST_2:
                            stack[sp++] = (float) (op - FCONST_0);
                            break;
                        case DCONST_0: case DCONST_1:
                            stack[sp++] = (double) (op - DCONST_0);
                            break;
                        case BIPUSH: case SIPUSH:
                            stack[sp++] = ((IntInsnNode) insn).operand;
                            break;
                        case LDC:
                            stack[sp++] = ldc(((LdcInsnNode) insn).cst);
                            break;
                        case ILOAD: case LLOAD: case FLOAD: case DLOAD: case ALOAD:
                            stack[sp++] = locals[((VarInsnNode) insn).var];
                            break;
                        case ISTORE: case LSTORE: case FSTORE: case DSTORE: case ASTORE:
                            locals[((VarInsnNode) insn).var] = stack[--sp];
                            break;
                        case IALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = ((int[]) stack[sp - 1])[idx];
                            break;
                        }
                        case LALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = ((long[]) stack[sp - 1])[idx];
                            break;
                        }
                        case FALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = ((float[]) stack[sp - 1])[idx];
                            break;
                        }
                        case DALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = ((double[]) stack[sp - 1])[idx];
                            break;
                        }
                        case AALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = ((RefArray) stack[sp - 1]).data[idx];
                            break;
                        }
                        case BALOAD: {
                            int idx = (Integer) stack[--sp];
                            Object a = stack[sp - 1];
                            if (a instanceof byte[] b) {
                                stack[sp - 1] = (int) b[idx];
                            } else {
                                stack[sp - 1] = ((boolean[]) a)[idx] ? 1 : 0;
                            }
                            break;
                        }
                        case CALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = (int) ((char[]) stack[sp - 1])[idx];
                            break;
                        }
                        case SALOAD: {
                            int idx = (Integer) stack[--sp];
                            stack[sp - 1] = (int) ((short[]) stack[sp - 1])[idx];
                            break;
                        }
                        case IASTORE: {
                            int v = (Integer) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            ((int[]) stack[--sp])[idx] = v;
                            break;
                        }
                        case LASTORE: {
                            long v = (Long) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            ((long[]) stack[--sp])[idx] = v;
                            break;
                        }
                        case FASTORE: {
                            float v = (Float) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            ((float[]) stack[--sp])[idx] = v;
                            break;
                        }
                        case DASTORE: {
                            double v = (Double) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            ((double[]) stack[--sp])[idx] = v;
                            break;
                        }
                        case AASTORE: {
                            Object v = stack[--sp];
                            int idx = (Integer) stack[--sp];
                            RefArray a = (RefArray) stack[--sp];
                            if (a == null) {
                                throw new NullPointerException();
                            }
                            if (idx < 0 || idx >= a.data.length) {
                                throw new ArrayIndexOutOfBoundsException("Index " + idx + " out of bounds for length " + a.data.length);
                            }
                            if (v != null && !classOf(v).isAssignableTo(a.cls.component)) {
                                throw error("java/lang/ArrayStoreException", classOf(v).javaName());
                            }
                            a.data[idx] = v;
                            break;
                        }
                        case BASTORE: {
                            int v = (Integer) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            Object a = stack[--sp];
                            if (a instanceof byte[] b) {
                                b[idx] = (byte) v;
                            } else {
                                ((boolean[]) a)[idx] = (v & 1) != 0;
                            }
                            break;
                        }
                        case CASTORE: {
                            int v = (Integer) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            ((char[]) stack[--sp])[idx] = (char) v;
                            break;
                        }
                        case SASTORE: {
                            int v = (Integer) stack[--sp];
                            int idx = (Integer) stack[--sp];
                            ((short[]) stack[--sp])[idx] = (short) v;
                            break;
                        }
                        case POP:
                            sp--;
                            break;
                        case POP2:
                            sp -= cat2(stack[sp - 1]) ? 1 : 2;
                            break;
                        case DUP:
                            stack[sp] = stack[sp - 1];
                            sp++;
                            break;
                        case DUP_X1: {
                            Object v1 = stack[sp - 1];
                            Object v2 = stack[sp - 2];
                            stack[sp - 2] = v1;
                            stack[sp - 1] = v2;
                            stack[sp++] = v1;
                            break;
                        }
                        case DUP_X2: {
                            Object v1 = stack[sp - 1];
                            Object v2 = stack[sp - 2];
                            if (cat2(v2)) {
                                stack[sp - 2] = v1;
                                stack[sp - 1] = v2;
                                stack[sp++] = v1;
                            } else {
                                Object v3 = stack[sp - 3];
                                stack[sp - 3] = v1;
                                stack[sp - 2] = v3;
                                stack[sp - 1] = v2;
                                stack[sp++] = v1;
                            }
                            break;
                        }
                        case DUP2: {
                            Object v1 = stack[sp - 1];
                            if (cat2(v1)) {
                                stack[sp++] = v1;
                            } else {
                                Object v2 = stack[sp - 2];
                                stack[sp++] = v2;
                                stack[sp++] = v1;
                            }
                            break;
                        }
                        case DUP2_X1: {
                            Object v1 = stack[sp - 1];
                            if (cat2(v1)) {
                                Object v2 = stack[sp - 2];
                                stack[sp - 2] = v1;
                                stack[sp - 1] = v2;
                                stack[sp++] = v1;
                            } else {
                                Object v2 = stack[sp - 2];
                                Object v3 = stack[sp - 3];
                                stack[sp - 3] = v2;
                                stack[sp - 2] = v1;
                                stack[sp - 1] = v3;
                                stack[sp++] = v2;
                                stack[sp++] = v1;
                            }
                            break;
                        }
                        case DUP2_X2: {
                            Object v1 = stack[sp - 1];
                            Object v2 = stack[sp - 2];
                            if (cat2(v1) && cat2(v2)) {
                                stack[sp - 2] = v1;
                                stack[sp - 1] = v2;
                                stack[sp++] = v1;
                            } else if (cat2(v1)) {
                                Object v3 = stack[sp - 3];
                                stack[sp - 3] = v1;
                                stack[sp - 2] = v3;
                                stack[sp - 1] = v2;
                                stack[sp++] = v1;
                            } else {
                                Object v3 = stack[sp - 3];
                                if (cat2(v3)) {
                                    stack[sp - 3] = v2;
                                    stack[sp - 2] = v1;
                                    stack[sp - 1] = v3;
                                    stack[sp++] = v2;
                                    stack[sp++] = v1;
                                } else {
                                    Object v4 = stack[sp - 4];
                                    stack[sp - 4] = v2;
                                    stack[sp - 3] = v1;
                                    stack[sp - 2] = v4;
                                    stack[sp - 1] = v3;
                                    stack[sp++] = v2;
                                    stack[sp++] = v1;
                                }
                            }
                            break;
                        }
                        case SWAP: {
                            Object v = stack[sp - 1];
                            stack[sp - 1] = stack[sp - 2];
                            stack[sp - 2] = v;
                            break;
                        }
                        case IADD: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] + b; break; }
                        case LADD: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] + b; break; }
                        case FADD: { float b = (Float) stack[--sp]; stack[sp - 1] = (Float) stack[sp - 1] + b; break; }
                        case DADD: { double b = (Double) stack[--sp]; stack[sp - 1] = (Double) stack[sp - 1] + b; break; }
                        case ISUB: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] - b; break; }
                        case LSUB: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] - b; break; }
                        case FSUB: { float b = (Float) stack[--sp]; stack[sp - 1] = (Float) stack[sp - 1] - b; break; }
                        case DSUB: { double b = (Double) stack[--sp]; stack[sp - 1] = (Double) stack[sp - 1] - b; break; }
                        case IMUL: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] * b; break; }
                        case LMUL: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] * b; break; }
                        case FMUL: { float b = (Float) stack[--sp]; stack[sp - 1] = (Float) stack[sp - 1] * b; break; }
                        case DMUL: { double b = (Double) stack[--sp]; stack[sp - 1] = (Double) stack[sp - 1] * b; break; }
                        case IDIV: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] / b; break; }
                        case LDIV: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] / b; break; }
                        case FDIV: { float b = (Float) stack[--sp]; stack[sp - 1] = (Float) stack[sp - 1] / b; break; }
                        case DDIV: { double b = (Double) stack[--sp]; stack[sp - 1] = (Double) stack[sp - 1] / b; break; }
                        case IREM: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] % b; break; }
                        case LREM: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] % b; break; }
                        case FREM: { float b = (Float) stack[--sp]; stack[sp - 1] = (Float) stack[sp - 1] % b; break; }
                        case DREM: { double b = (Double) stack[--sp]; stack[sp - 1] = (Double) stack[sp - 1] % b; break; }
                        case INEG: stack[sp - 1] = -(Integer) stack[sp - 1]; break;
                        case LNEG: stack[sp - 1] = -(Long) stack[sp - 1]; break;
                        case FNEG: stack[sp - 1] = -(Float) stack[sp - 1]; break;
                        case DNEG: stack[sp - 1] = -(Double) stack[sp - 1]; break;
                        case ISHL: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] << b; break; }
                        case LSHL: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] << b; break; }
                        case ISHR: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] >> b; break; }
                        case LSHR: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] >> b; break; }
                        case IUSHR: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] >>> b; break; }
                        case LUSHR: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] >>> b; break; }
                        case IAND: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] & b; break; }
                        case LAND: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] & b; break; }
                        case IOR: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] | b; break; }
                        case LOR: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] | b; break; }
                        case IXOR: { int b = (Integer) stack[--sp]; stack[sp - 1] = (Integer) stack[sp - 1] ^ b; break; }
                        case LXOR: { long b = (Long) stack[--sp]; stack[sp - 1] = (Long) stack[sp - 1] ^ b; break; }
                        case IINC: {
                            IincInsnNode ii = (IincInsnNode) insn;
                            locals[ii.var] = (Integer) locals[ii.var] + ii.incr;
                            break;
                        }
                        case I2L: stack[sp - 1] = (long) (Integer) stack[sp - 1]; break;
                        case I2F: stack[sp - 1] = (float) (Integer) stack[sp - 1]; break;
                        case I2D: stack[sp - 1] = (double) (Integer) stack[sp - 1]; break;
                        case L2I: stack[sp - 1] = (int) (long) (Long) stack[sp - 1]; break;
                        case L2F: stack[sp - 1] = (float) (Long) stack[sp - 1]; break;
                        case L2D: stack[sp - 1] = (double) (Long) stack[sp - 1]; break;
                        case F2I: stack[sp - 1] = (int) (float) (Float) stack[sp - 1]; break;
                        case F2L: stack[sp - 1] = (long) (float) (Float) stack[sp - 1]; break;
                        case F2D: stack[sp - 1] = (double) (Float) stack[sp - 1]; break;
                        case D2I: stack[sp - 1] = (int) (double) (Double) stack[sp - 1]; break;
                        case D2L: stack[sp - 1] = (long) (double) (Double) stack[sp - 1]; break;
                        case D2F: stack[sp - 1] = (float) (double) (Double) stack[sp - 1]; break;
                        case I2B: stack[sp - 1] = (int) (byte) (int) (Integer) stack[sp - 1]; break;
                        case I2C: stack[sp - 1] = (int) (char) (int) (Integer) stack[sp - 1]; break;
                        case I2S: stack[sp - 1] = (int) (short) (int) (Integer) stack[sp - 1]; break;
                        case LCMP: { long b = (Long) stack[--sp]; stack[sp - 1] = Long.compare((Long) stack[sp - 1], b); break; }
                        case FCMPL: case FCMPG: {
                            float b = (Float) stack[--sp];
                            float a = (Float) stack[sp - 1];
                            stack[sp - 1] = Float.isNaN(a) || Float.isNaN(b) ? (op == FCMPG ? 1 : -1) : (a < b ? -1 : a > b ? 1 : 0);
                            break;
                        }
                        case DCMPL: case DCMPG: {
                            double b = (Double) stack[--sp];
                            double a = (Double) stack[sp - 1];
                            stack[sp - 1] = Double.isNaN(a) || Double.isNaN(b) ? (op == DCMPG ? 1 : -1) : (a < b ? -1 : a > b ? 1 : 0);
                            break;
                        }
                        case IFEQ: case IFNE: case IFLT: case IFGE: case IFGT: case IFLE: {
                            int v = (Integer) stack[--sp];
                            boolean jump = switch (op) {
                                case IFEQ -> v == 0;
                                case IFNE -> v != 0;
                                case IFLT -> v < 0;
                                case IFGE -> v >= 0;
                                case IFGT -> v > 0;
                                default -> v <= 0;
                            };
                            if (jump) {
                                pc = target(m, insn, pc);
                                continue;
                            }
                            break;
                        }
                        case IF_ICMPEQ: case IF_ICMPNE: case IF_ICMPLT: case IF_ICMPGE: case IF_ICMPGT: case IF_ICMPLE: {
                            int b = (Integer) stack[--sp];
                            int a = (Integer) stack[--sp];
                            boolean jump = switch (op) {
                                case IF_ICMPEQ -> a == b;
                                case IF_ICMPNE -> a != b;
                                case IF_ICMPLT -> a < b;
                                case IF_ICMPGE -> a >= b;
                                case IF_ICMPGT -> a > b;
                                default -> a <= b;
                            };
                            if (jump) {
                                pc = target(m, insn, pc);
                                continue;
                            }
                            break;
                        }
                        case IF_ACMPEQ: case IF_ACMPNE: {
                            Object b = stack[--sp];
                            Object a = stack[--sp];
                            if ((a == b) == (op == IF_ACMPEQ)) {
                                pc = target(m, insn, pc);
                                continue;
                            }
                            break;
                        }
                        case IFNULL: case IFNONNULL: {
                            Object a = stack[--sp];
                            if ((a == null) == (op == IFNULL)) {
                                pc = target(m, insn, pc);
                                continue;
                            }
                            break;
                        }
                        case GOTO:
                            pc = target(m, insn, pc);
                            continue;
                        case JSR: case RET:
                            throw new IllegalStateException("jsr/ret not supported in " + m);
                        case TABLESWITCH: {
                            int v = (Integer) stack[--sp];
                            TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                            int[] t = switchTargets(m, pc);
                            pc = v >= ts.min && v <= ts.max ? t[v - ts.min] : t[t.length - 1];
                            continue;
                        }
                        case LOOKUPSWITCH: {
                            int v = (Integer) stack[--sp];
                            LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                            int[] t = switchTargets(m, pc);
                            int to = t[t.length - 1];
                            for (int k = 0; k < ls.keys.size(); k++) {
                                if (ls.keys.get(k) == v) {
                                    to = t[k];
                                    break;
                                }
                            }
                            pc = to;
                            continue;
                        }
                        case IRETURN: case LRETURN: case FRETURN: case DRETURN: case ARETURN:
                            return stack[sp - 1];
                        case RETURN:
                            return null;
                        case GETSTATIC: {
                            VField f = staticField(m, pc, (FieldInsnNode) insn);
                            if (f == null) {
                                stack[sp++] = systemStream((FieldInsnNode) insn);
                            } else {
                                stack[sp++] = f.owner.statics[f.slot];
                            }
                            break;
                        }
                        case PUTSTATIC: {
                            VField f = staticField(m, pc, (FieldInsnNode) insn);
                            f.owner.statics[f.slot] = stack[--sp];
                            break;
                        }
                        case GETFIELD: {
                            VField f = instanceField(m, pc, (FieldInsnNode) insn);
                            stack[sp - 1] = ((VObject) stack[sp - 1]).fields[f.slot];
                            break;
                        }
                        case PUTFIELD: {
                            VField f = instanceField(m, pc, (FieldInsnNode) insn);
                            Object v = stack[--sp];
                            ((VObject) stack[--sp]).fields[f.slot] = v;
                            break;
                        }
                        case INVOKEVIRTUAL: case INVOKESPECIAL: case INVOKESTATIC: case INVOKEINTERFACE: {
                            MethodInsnNode mi = (MethodInsnNode) insn;
                            Object link = links[pc];
                            int argc;
                            if (link == null) {
                                link = linkMethod(mi);
                                links[pc] = link;
                            }
                            argc = ((Linked) link).argc;
                            Object[] args = new Object[argc];
                            sp -= argc;
                            System.arraycopy(stack, sp, args, 0, argc);
                            Object r = ((Linked) link).call(this, args);
                            if (!((Linked) link).isVoid) {
                                stack[sp++] = r;
                            }
                            break;
                        }
                        case INVOKEDYNAMIC: {
                            Object link = links[pc];
                            if (link == null) {
                                link = Dynamic.link(this, m, (InvokeDynamicInsnNode) insn);
                                links[pc] = link;
                            }
                            Linked l = (Linked) link;
                            Object[] args = new Object[l.argc];
                            sp -= l.argc;
                            System.arraycopy(stack, sp, args, 0, l.argc);
                            Object r = l.call(this, args);
                            if (!l.isVoid) {
                                stack[sp++] = r;
                            }
                            break;
                        }
                        case NEW: {
                            VClass c = classLink(m, pc, ((TypeInsnNode) insn).desc);
                            stack[sp++] = newObject(c);
                            break;
                        }
                        case NEWARRAY: {
                            int n = (Integer) stack[sp - 1];
                            if (n < 0) {
                                throw error("java/lang/NegativeArraySizeException", String.valueOf(n));
                            }
                            stack[sp - 1] = switch (((IntInsnNode) insn).operand) {
                                case T_BOOLEAN -> new boolean[n];
                                case T_CHAR -> new char[n];
                                case T_FLOAT -> new float[n];
                                case T_DOUBLE -> new double[n];
                                case T_BYTE -> new byte[n];
                                case T_SHORT -> new short[n];
                                case T_INT -> new int[n];
                                default -> new long[n];
                            };
                            break;
                        }
                        case ANEWARRAY: {
                            int n = (Integer) stack[sp - 1];
                            if (n < 0) {
                                throw error("java/lang/NegativeArraySizeException", String.valueOf(n));
                            }
                            VClass c = classLink(m, pc, ((TypeInsnNode) insn).desc);
                            stack[sp - 1] = new RefArray(arrayOf(c), n);
                            break;
                        }
                        case MULTIANEWARRAY: {
                            MultiANewArrayInsnNode ma = (MultiANewArrayInsnNode) insn;
                            int[] dims = new int[ma.dims];
                            for (int k = ma.dims - 1; k >= 0; k--) {
                                dims[k] = (Integer) stack[--sp];
                            }
                            stack[sp++] = multiArray(load(ma.desc), dims, 0);
                            break;
                        }
                        case ARRAYLENGTH:
                            stack[sp - 1] = arrayLength(stack[sp - 1]);
                            break;
                        case ATHROW: {
                            Object e = stack[--sp];
                            if (e == null) {
                                throw new NullPointerException();
                            }
                            throw new GuestException((VObject) e);
                        }
                        case CHECKCAST: {
                            Object v = stack[sp - 1];
                            if (v != null) {
                                VClass c = classLink(m, pc, ((TypeInsnNode) insn).desc);
                                if (!classOf(v).isAssignableTo(c)) {
                                    throw error("java/lang/ClassCastException",
                                            classOf(v).javaName() + " cannot be cast to " + c.javaName());
                                }
                            }
                            break;
                        }
                        case INSTANCEOF: {
                            Object v = stack[sp - 1];
                            if (v == null) {
                                stack[sp - 1] = 0;
                            } else {
                                VClass c = classLink(m, pc, ((TypeInsnNode) insn).desc);
                                stack[sp - 1] = classOf(v).isAssignableTo(c) ? 1 : 0;
                            }
                            break;
                        }
                        case MONITORENTER: case MONITOREXIT:
                            if (stack[--sp] == null) {
                                throw new NullPointerException();
                            }
                            break;
                        default:
                            throw new IllegalStateException("opcode " + op + " in " + m);
                    }
                    pc++;
                }
            } catch (GuestException e) {
                int h = handler(m, pc, e.exception);
                if (h < 0) {
                    throw e;
                }
                sp = 0;
                stack[sp++] = e.exception;
                pc = h;
            } catch (NullPointerException | ArrayIndexOutOfBoundsException | ArithmeticException
                     | NegativeArraySizeException e) {
                // Host exceptions raised by guest operations on guest values become guest exceptions.
                if (trace) {
                    System.err.println("[vm] host " + e + " in " + m + " at pc " + pc + " line " + m.lines[pc]);
                    if (System.getenv("VM_TRACE_HOST") != null) {
                        e.printStackTrace();
                    }
                }
                String cls = e instanceof NullPointerException ? "java/lang/NullPointerException"
                        : e instanceof ArrayIndexOutOfBoundsException ? "java/lang/ArrayIndexOutOfBoundsException"
                        : e instanceof ArithmeticException ? "java/lang/ArithmeticException"
                        : "java/lang/NegativeArraySizeException";
                String msg = e instanceof NullPointerException ? null : e.getMessage();
                GuestException ge = error(cls, msg);
                int h = handler(m, pc, ge.exception);
                if (h < 0) {
                    throw ge;
                }
                sp = 0;
                stack[sp++] = ge.exception;
                pc = h;
            }
        }
    }

    private int handler(VMethod m, int pc, VObject exception) {
        for (int i = 0; i < m.tryStart.length; i++) {
            if (pc >= m.tryStart[i] && pc < m.tryEnd[i]) {
                if (m.tryType[i] == null) {
                    return m.tryHandler[i];
                }
                if (m.tryClass[i] == null) {
                    try {
                        m.tryClass[i] = tryLoad(m.tryType[i]);
                    } catch (GuestException e) {
                        m.tryClass[i] = null; // unloadable, so nothing thrown can be an instance
                    }
                    if (m.tryClass[i] == null) {
                        continue;
                    }
                }
                if (exception.cls.isAssignableTo(m.tryClass[i])) {
                    return m.tryHandler[i];
                }
            }
        }
        return -1;
    }

    private int target(VMethod m, AbstractInsnNode insn, int pc) {
        Object l = m.links[pc];
        if (l == null) {
            l = m.node.instructions.indexOf(((JumpInsnNode) insn).label);
            m.links[pc] = l;
        }
        return (Integer) l;
    }

    private int[] switchTargets(VMethod m, int pc) {
        Object l = m.links[pc];
        if (l == null) {
            AbstractInsnNode insn = m.code[pc];
            List<org.objectweb.asm.tree.LabelNode> labels;
            org.objectweb.asm.tree.LabelNode dflt;
            if (insn instanceof TableSwitchInsnNode ts) {
                labels = ts.labels;
                dflt = ts.dflt;
            } else {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                labels = ls.labels;
                dflt = ls.dflt;
            }
            int[] t = new int[labels.size() + 1];
            for (int i = 0; i < labels.size(); i++) {
                t[i] = m.node.instructions.indexOf(labels.get(i));
            }
            t[labels.size()] = m.node.instructions.indexOf(dflt);
            l = t;
            m.links[pc] = l;
        }
        return (int[]) l;
    }

    private VClass classLink(VMethod m, int pc, String desc) {
        Object l = m.links[pc];
        if (l == null) {
            l = load(desc);
            m.links[pc] = l;
        }
        return (VClass) l;
    }

    private VField staticField(VMethod m, int pc, FieldInsnNode fi) {
        Object l = m.links[pc];
        if (l == null) {
            VClass c = load(fi.owner);
            VField f = findField(c, fi.name);
            if (f == null) {
                if (fi.owner.equals("java/lang/System")) {
                    return null; // System.out/err/in: methods in TeaVM, see systemStream
                }
                throw error("java/lang/NoSuchFieldError", fi.owner.replace('/', '.') + "." + fi.name);
            }
            initialize(f.owner);
            l = f;
            m.links[pc] = l;
        }
        return (VField) l;
    }

    /**
     * TeaVM's System has {@code out()}/{@code err()}/{@code in()} methods instead of fields; its
     * compiler rewrites the field reads. So does this VM.
     */
    private Object systemStream(FieldInsnNode fi) {
        return callStatic("java/lang/System", fi.name + "()" + fi.desc);
    }

    private VField instanceField(VMethod m, int pc, FieldInsnNode fi) {
        Object l = m.links[pc];
        if (l == null) {
            VField f = findField(load(fi.owner), fi.name);
            if (f == null || f.isStatic) {
                throw error("java/lang/NoSuchFieldError", fi.owner.replace('/', '.') + "." + fi.name);
            }
            l = f;
            m.links[pc] = l;
        }
        return (VField) l;
    }

    Object ldc(Object cst) {
        if (cst instanceof String s) {
            return intern(s);
        }
        if (cst instanceof Type t) {
            if (t.getSort() == Type.METHOD) {
                throw new IllegalStateException("MethodType constants are not supported");
            }
            return classObject(load(t.getSort() == Type.ARRAY ? t.getDescriptor() : t.getInternalName()));
        }
        if (cst instanceof Handle || cst instanceof org.objectweb.asm.ConstantDynamic) {
            throw new IllegalStateException("constant " + cst + " is not supported");
        }
        return cst;
    }

    int arrayLength(Object a) {
        if (a instanceof RefArray r) {
            return r.data.length;
        }
        if (a == null) {
            throw new NullPointerException();
        }
        return java.lang.reflect.Array.getLength(a);
    }

    Object newArray(VClass component, int n) {
        if (component.isPrimitive()) {
            return switch (component.primitive) {
                case 'Z' -> new boolean[n];
                case 'B' -> new byte[n];
                case 'C' -> new char[n];
                case 'S' -> new short[n];
                case 'I' -> new int[n];
                case 'J' -> new long[n];
                case 'F' -> new float[n];
                case 'D' -> new double[n];
                default -> throw error("java/lang/IllegalArgumentException", "void[]");
            };
        }
        return new RefArray(arrayOf(component), n);
    }

    private Object multiArray(VClass arrayClass, int[] dims, int d) {
        Object a = newArray(arrayClass.component, dims[d]);
        if (d + 1 < dims.length) {
            Object[] data = ((RefArray) a).data;
            for (int i = 0; i < data.length; i++) {
                data[i] = multiArray(arrayClass.component, dims, d + 1);
            }
        }
        return a;
    }

    // ---------------------------------------------------------------- method linking

    /** A linked call site. */
    abstract static class Linked {
        final int argc;
        final boolean isVoid;

        Linked(int argc, boolean isVoid) {
            this.argc = argc;
            this.isVoid = isVoid;
        }

        abstract Object call(VM vm, Object[] args);
    }

    private Linked linkMethod(MethodInsnNode mi) {
        int argc = Type.getArgumentTypes(mi.desc).length + (mi.getOpcode() == INVOKESTATIC ? 0 : 1);
        boolean isVoid = Type.getReturnType(mi.desc) == Type.VOID_TYPE;
        String nd = mi.name + mi.desc;
        if (mi.owner.startsWith("[")) {
            // Methods of arrays: clone() is special, the rest are Object's.
            if (mi.name.equals("clone")) {
                return new Linked(argc, false) {
                    @Override
                    Object call(VM vm, Object[] args) {
                        return cloneArray(args[0]);
                    }
                };
            }
        }
        switch (mi.getOpcode()) {
            case INVOKESTATIC: {
                VClass c = load(mi.owner);
                VMethod target = findMethod(c, nd);
                if (target == null) {
                    throw error("java/lang/NoSuchMethodError", mi.owner.replace('/', '.') + "." + nd);
                }
                return new Linked(argc, isVoid) {
                    @Override
                    Object call(VM vm, Object[] args) {
                        vm.initialize(target.owner);
                        return vm.invoke(target, args);
                    }
                };
            }
            case INVOKESPECIAL: {
                VClass c = load(mi.owner);
                VMethod target = findMethod(c, nd);
                if (target == null) {
                    throw error("java/lang/NoSuchMethodError", mi.owner.replace('/', '.') + "." + nd);
                }
                return new Linked(argc, isVoid) {
                    @Override
                    Object call(VM vm, Object[] args) {
                        if (args[0] == null) {
                            throw new NullPointerException();
                        }
                        return vm.invoke(target, args);
                    }
                };
            }
            default: {
                if (!mi.owner.startsWith("[")) {
                    load(mi.owner); // NoClassDefFoundError at the call site, as resolution would
                }
                return new Linked(argc, isVoid) {
                    VClass lastClass;
                    VMethod lastTarget;

                    @Override
                    Object call(VM vm, Object[] args) {
                        Object recv = args[0];
                        if (recv == null) {
                            throw new NullPointerException();
                        }
                        VClass rc = vm.classOf(recv);
                        VMethod target;
                        if (rc == lastClass) {
                            target = lastTarget;
                        } else {
                            target = vm.virtualMethod(rc, nd);
                            lastClass = rc;
                            lastTarget = target;
                        }
                        return vm.invoke(target, args);
                    }
                };
            }
        }
    }

    Object cloneArray(Object a) {
        if (a instanceof RefArray r) {
            return new RefArray(r.cls, r.data.clone());
        }
        if (a instanceof int[] x) return x.clone();
        if (a instanceof char[] x) return x.clone();
        if (a instanceof byte[] x) return x.clone();
        if (a instanceof boolean[] x) return x.clone();
        if (a instanceof long[] x) return x.clone();
        if (a instanceof double[] x) return x.clone();
        if (a instanceof float[] x) return x.clone();
        if (a instanceof short[] x) return x.clone();
        throw new NullPointerException();
    }

    /** The guest stack, innermost first, skipping {@code skip} frames. */
    List<Frame> stackSnapshot(int skip) {
        List<Frame> out = new ArrayList<>();
        for (int i = frames.size() - 1 - skip; i >= 0; i--) {
            out.add(frames.get(i));
        }
        return out;
    }
}
