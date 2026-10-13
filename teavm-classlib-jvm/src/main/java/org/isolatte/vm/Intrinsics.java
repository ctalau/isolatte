package org.isolatte.vm;

import java.io.PrintStream;
import java.util.List;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InnerClassNode;

/**
 * The VM side of TeaVM's class library: implementations of the methods that TeaVM's compiler
 * generates per backend ({@code native} methods: {@code @Intrinsified}, {@code @GeneratedBy},
 * {@code @JSBody}, ...), plus a few non-native methods whose bytecode only works on a TeaVM target
 * ({@code identity()} goes through JavaScript's {@code Platform}, {@code fillInStackTrace()} needs a
 * native stack). The guest runs with every {@code PlatformDetector} check false, i.e. the plain-Java
 * code paths.
 */
final class Intrinsics {
    private final VM vm;
    private final PrintStream out;
    private final PrintStream err;
    private int nextId;
    private VClass platformObject;

    private Intrinsics(VM vm, PrintStream out, PrintStream err) {
        this.vm = vm;
        this.out = out;
        this.err = err;
    }

    static void register(VM vm, PrintStream out, PrintStream err) {
        new Intrinsics(vm, out, err).registerAll();
    }

    private void put(String key, Native n) {
        vm.natives.put(key, n);
    }

    private static int i(Object o) {
        return (Integer) o;
    }

    private static Object bool(boolean b) {
        return b ? 1 : 0;
    }

    private VClass cls(Object classInfo) {
        return (VClass) ((VObject) classInfo).hidden;
    }

    private void registerAll() {
        object();
        string();
        system();
        numbers();
        classInfo();
        throwable();
        patches();
        compileTime();
    }

    /**
     * Places where TeaVM's class library differs from Java SE in a way that breaks Xerces, patched at
     * the VM level (every entry is listed in the README).
     */
    private void patches() {
        // TeaVM returns a new, mostly empty SecurityManager; Java SE returns null when none is
        // installed (always, since JDK 18). Xerces calls checkPackageAccess on a non-null one.
        put("java/lang/System.getSecurityManager()Ljava/lang/SecurityManager;", a -> null);

        // TeaVM's ClassLoader has no loadClass: its world is closed at compile time.
        add("java/lang/ClassLoader", "loadClass(Ljava/lang/String;)Ljava/lang/Class;", a -> loadClass(a[1]));
        add("java/lang/ClassLoader", "loadClass(Ljava/lang/String;Z)Ljava/lang/Class;", a -> loadClass(a[1]));
        // TeaVM embeds the resources it was told about at compile time and serves them from a JS
        // object. Here, resources come from the guest class path (fixed by the VM, read-only).
        put("java/lang/ClassLoader.getResourceAsStream(Ljava/lang/String;)Ljava/io/InputStream;", a -> {
            String name = VM.host(a[1]);
            byte[] bytes = name == null ? null : vm.loader.resource(name.startsWith("/") ? name.substring(1) : name);
            return bytes == null ? null : vm.construct("java/io/ByteArrayInputStream", "([B)V", (Object) bytes);
        });
    }

    /**
     * TeaVM-compile-time code (metaprogramming {@code @Meta} natives) replaced by guest classes in
     * work/vm-guest.
     */
    private void compileTime() {
        put("org/teavm/classlib/impl/ResourceBundleImpl.createBundleMap(Z)Ljava/util/Map;",
                a -> vm.construct("org/isolatte/guest/BundleMap", "()V"));
    }

    private void add(String className, String nameDesc, Native n) {
        vm.additions.computeIfAbsent(className, k -> new java.util.HashMap<>()).put(nameDesc, n);
    }

    private Object loadClass(Object guestName) {
        String name = VM.host(guestName);
        VClass k = name == null || name.contains("/") ? null : vm.tryLoad(name.replace('.', '/'));
        if (k == null) {
            throw vm.error("java/lang/ClassNotFoundException", name);
        }
        return vm.classObject(k);
    }

    // ------------------------------------------------------------------ java.lang.Object

    private void object() {
        String o = "java/lang/Object.";
        put(o + "getObjectClassInfo(Ljava/lang/Object;)Lorg/teavm/runtime/reflect/ClassInfo;",
                a -> vm.classInfo(vm.classOf(a[0])));
        put(o + "identity()I", a -> System.identityHashCode(a[0]));
        put(o + "cloneObject()Ljava/lang/Object;", a -> {
            if (!(a[0] instanceof VObject src)) {
                return vm.cloneArray(a[0]);
            }
            VObject copy = new VObject(src.cls);
            System.arraycopy(src.fields, 0, copy.fields, 0, src.fields.length);
            copy.hidden = src.hidden;
            return copy;
        });
        put("org/teavm/platform/Platform.clone(Ljava/lang/Object;)Ljava/lang/Object;",
                a -> vm.natives.get(o + "cloneObject()Ljava/lang/Object;").call(a));
        put("org/teavm/platform/Platform.nextObjectId()I", a -> ++nextId);
        // PlatformObject is TeaVM's view of a JS object; here it only carries the identity hash.
        put("org/teavm/platform/Platform.getPlatformObject(Ljava/lang/Object;)Lorg/teavm/platform/PlatformObject;", a -> {
            if (platformObject == null) {
                java.util.Map<String, Native> m = new java.util.LinkedHashMap<>();
                m.put("getId()I", x -> System.identityHashCode(((VObject) x[0]).hidden));
                m.put("setId(I)V", x -> null);
                platformObject = vm.synthetic("org/teavm/platform/PlatformObject$$VM", List.of(vm.load("org/teavm/platform/PlatformObject")), m, null);
            }
            VObject p = new VObject(platformObject);
            p.hidden = a[0];
            return p;
        });
        // Single-threaded: notify has no one to wake, wait would wait forever.
        put(o + "notify()V", a -> null);
        put(o + "notifyAll()V", a -> null);
    }

    // ------------------------------------------------------------------ java.lang.String

    private void string() {
        String s = "java/lang/String.";
        put(s + "initWithEmptyChars()V", a -> {
            ((VObject) a[0]).hidden = "";
            return null;
        });
        put(s + "borrowChars(Ljava/lang/String;)V", a -> {
            ((VObject) a[0]).hidden = ((VObject) a[1]).hidden;
            return null;
        });
        put(s + "initWithCharArray([CII)V", a -> {
            ((VObject) a[0]).hidden = new String((char[]) a[1], i(a[2]), i(a[3]));
            return null;
        });
        put(s + "takeCharArray([C)V", a -> {
            ((VObject) a[0]).hidden = new String((char[]) a[1]);
            return null;
        });
        put(s + "charactersLength()I", a -> VM.host(a[0]).length());
        put(s + "charactersGet(I)C", a -> {
            String str = VM.host(a[0]);
            int idx = i(a[1]);
            if (idx < 0 || idx >= str.length()) {
                throw vm.error("java/lang/StringIndexOutOfBoundsException", null);
            }
            return (int) str.charAt(idx);
        });
        put(s + "copyCharsToArray(I[CII)V", a -> {
            int begin = i(a[1]);
            VM.host(a[0]).getChars(begin, begin + i(a[4]), (char[]) a[2], i(a[3]));
            return null;
        });
        put(s + "fastCharArray()[C", a -> VM.host(a[0]).toCharArray());
        put(s + "intern()Ljava/lang/String;", a -> vm.intern(VM.host(a[0])));
    }

    // ------------------------------------------------------------------ java.lang.System, console

    private void system() {
        put("java/lang/System.doArrayCopy(Ljava/lang/Object;ILjava/lang/Object;II)V", a -> {
            Object src = a[0] instanceof RefArray r ? r.data : a[0];
            Object dst = a[2] instanceof RefArray r ? r.data : a[2];
            System.arraycopy(src, i(a[1]), dst, i(a[3]), i(a[4]));
            return null;
        });
        put("java/lang/System.currentTimeMillis()J", a -> System.currentTimeMillis());
        put("java/lang/System.nanoTime()J", a -> System.nanoTime());
        put("org/teavm/classlib/impl/console/Console.writeStdout([BII)V", a -> {
            out.write((byte[]) a[0], i(a[1]), i(a[2]));
            out.flush();
            return null;
        });
        put("org/teavm/classlib/impl/console/Console.writeStderr([BII)V", a -> {
            err.write((byte[]) a[0], i(a[1]), i(a[2]));
            err.flush();
            return null;
        });
    }

    // ------------------------------------------------------------------ numbers and math

    private void numbers() {
        put("java/lang/Double.doubleToRawLongBits(D)J", a -> Double.doubleToRawLongBits((Double) a[0]));
        put("java/lang/Double.longBitsToDouble(J)D", a -> Double.longBitsToDouble((Long) a[0]));
        put("java/lang/Double.isNaN(D)Z", a -> bool(Double.isNaN((Double) a[0])));
        put("java/lang/Double.isFinite(D)Z", a -> bool(Double.isFinite((Double) a[0])));
        put("java/lang/Float.floatToRawIntBits(F)I", a -> Float.floatToRawIntBits((Float) a[0]));
        put("java/lang/Float.intBitsToFloat(I)F", a -> Float.intBitsToFloat(i(a[0])));
        put("java/lang/Float.isNaN(F)Z", a -> bool(Float.isNaN((Float) a[0])));
        put("java/lang/Float.isFinite(F)Z", a -> bool(Float.isFinite((Float) a[0])));
        put("java/lang/Integer.compare(II)I", a -> Integer.compare(i(a[0]), i(a[1])));
        put("java/lang/Integer.compareUnsigned(II)I", a -> Integer.compareUnsigned(i(a[0]), i(a[1])));
        put("java/lang/Integer.divideUnsigned(II)I", a -> Integer.divideUnsigned(i(a[0]), i(a[1])));
        put("java/lang/Integer.remainderUnsigned(II)I", a -> Integer.remainderUnsigned(i(a[0]), i(a[1])));
        put("java/lang/Long.compare(JJ)I", a -> Long.compare((Long) a[0], (Long) a[1]));
        put("java/lang/Long.compareUnsigned(JJ)I", a -> Long.compareUnsigned((Long) a[0], (Long) a[1]));
        put("java/lang/Long.divideUnsigned(JJ)J", a -> Long.divideUnsigned((Long) a[0], (Long) a[1]));
        put("java/lang/Long.remainderUnsigned(JJ)J", a -> Long.remainderUnsigned((Long) a[0], (Long) a[1]));
        String m = "java/lang/Math.";
        put(m + "sin(D)D", a -> Math.sin((Double) a[0]));
        put(m + "cos(D)D", a -> Math.cos((Double) a[0]));
        put(m + "tan(D)D", a -> Math.tan((Double) a[0]));
        put(m + "asin(D)D", a -> Math.asin((Double) a[0]));
        put(m + "acos(D)D", a -> Math.acos((Double) a[0]));
        put(m + "atan(D)D", a -> Math.atan((Double) a[0]));
        put(m + "exp(D)D", a -> Math.exp((Double) a[0]));
        put(m + "log(D)D", a -> Math.log((Double) a[0]));
        put(m + "sqrt(D)D", a -> Math.sqrt((Double) a[0]));
        put(m + "ceil(D)D", a -> Math.ceil((Double) a[0]));
        put(m + "floor(D)D", a -> Math.floor((Double) a[0]));
        put(m + "powImpl(DD)D", a -> Math.pow((Double) a[0], (Double) a[1]));
        put(m + "atan2(DD)D", a -> Math.atan2((Double) a[0], (Double) a[1]));
        put(m + "randomImpl()D", a -> Math.random());
        put(m + "minImpl(DD)F", a -> (float) Math.min((Double) a[0], (Double) a[1]));
        put(m + "maxImpl(DD)F", a -> (float) Math.max((Double) a[0], (Double) a[1]));
        put(m + "minImpl(FF)F", a -> Math.min((Float) a[0], (Float) a[1]));
        put(m + "maxImpl(FF)F", a -> Math.max((Float) a[0], (Float) a[1]));
        put(m + "absImpl(F)F", a -> Math.abs((Float) a[0]));
        put(m + "absImpl(D)D", a -> Math.abs((Double) a[0]));
        put(m + "sign(D)D", a -> Math.signum((Double) a[0]));
        put(m + "sign(F)F", a -> Math.signum((Float) a[0]));
    }

    // ------------------------------------------------------------------ reflection metadata

    private VObject stringInfo(String s) {
        if (s == null) {
            return null;
        }
        VObject o = new VObject(vm.stringInfoClass);
        o.hidden = s;
        return o;
    }

    private InnerClassNode innerEntry(VClass c) {
        if (c.node == null || c.node.innerClasses == null) {
            return null;
        }
        for (InnerClassNode n : c.node.innerClasses) {
            if (n.name.equals(c.name)) {
                return n;
            }
        }
        return null;
    }

    private static int modifiers(int jvm) {
        int m = jvm & 0xFFF & ~Opcodes.ACC_SUPER;
        if ((jvm & Opcodes.ACC_SYNTHETIC) != 0) {
            m |= 1 << 15;
        }
        if ((jvm & Opcodes.ACC_ANNOTATION) != 0) {
            m |= 1 << 13;
        }
        if ((jvm & Opcodes.ACC_ENUM) != 0) {
            m |= 1 << 16;
        }
        return m;
    }

    private void classInfo() {
        String c = "org/teavm/runtime/reflect/ClassInfo.";
        put("org/teavm/runtime/StringInfo.getStringObject()Ljava/lang/String;", a -> vm.str((String) ((VObject) a[0]).hidden));
        put(c + "modifiers()I", a -> {
            VClass k = cls(a[0]);
            InnerClassNode inner = innerEntry(k);
            return modifiers(inner != null ? inner.access : k.access);
        });
        put(c + "primitiveKind()I", a -> {
            VClass k = cls(a[0]);
            return k.isPrimitive() ? "-ZBSCIJFDV".indexOf(k.primitive) : 0;
        });
        put(c + "name()Lorg/teavm/runtime/StringInfo;", a -> {
            VClass k = cls(a[0]);
            return k.isArray() ? null : stringInfo(k.javaName());
        });
        put(c + "simpleName()Lorg/teavm/runtime/StringInfo;", a -> {
            InnerClassNode inner = innerEntry(cls(a[0]));
            return inner != null && inner.innerName != null ? stringInfo(inner.innerName) : null;
        });
        put(c + "itemType()Lorg/teavm/runtime/reflect/ClassInfo;", a -> {
            VClass k = cls(a[0]);
            return k.isArray() ? vm.classInfo(k.component) : null;
        });
        put(c + "arrayType()Lorg/teavm/runtime/reflect/ClassInfo;", a -> vm.classInfo(vm.arrayOf(cls(a[0]))));
        put(c + "declaringClass()Lorg/teavm/runtime/reflect/ClassInfo;", a -> {
            InnerClassNode inner = innerEntry(cls(a[0]));
            return inner != null && inner.outerName != null ? vm.classInfo(vm.load(inner.outerName)) : null;
        });
        put(c + "enclosingClass()Lorg/teavm/runtime/reflect/ClassInfo;", a -> {
            VClass k = cls(a[0]);
            InnerClassNode inner = innerEntry(k);
            if (inner == null) {
                return null;
            }
            String outer = inner.outerName != null ? inner.outerName : k.node.outerClass;
            return outer != null ? vm.classInfo(vm.load(outer)) : null;
        });
        put(c + "isSuperTypeOf(Lorg/teavm/runtime/reflect/ClassInfo;)Z", a -> bool(cls(a[1]).isAssignableTo(cls(a[0]))));
        put(c + "parent()Lorg/teavm/runtime/reflect/ClassInfo;", a -> {
            VClass k = cls(a[0]);
            return k.isInterface() || k.isPrimitive() || k.superClass == null ? null : vm.classInfo(k.superClass);
        });
        put(c + "superinterfaceCount()I", a -> cls(a[0]).interfaces.length);
        put(c + "superinterface(I)Lorg/teavm/runtime/reflect/ClassInfo;", a -> vm.classInfo(cls(a[0]).interfaces[i(a[1])]));
        put(c + "enumConstantCount()I", a -> enumConstants(cls(a[0])).data.length);
        put(c + "enumConstant(I)Ljava/lang/Object;", a -> enumConstants(cls(a[0])).data[i(a[1])]);
        put(c + "newArrayInstance(I)Ljava/lang/Object;", a -> vm.newArray(cls(a[0]), i(a[1])));
        put(c + "arrayLength(Ljava/lang/Object;)I", a -> vm.arrayLength(a[1]));
        put(c + "getItem(Ljava/lang/Object;I)Ljava/lang/Object;", a -> {
            int idx = i(a[2]);
            Object arr = a[1];
            if (arr instanceof RefArray r) {
                return r.data[idx];
            }
            VClass comp = vm.classOf(arr).component;
            Object v = java.lang.reflect.Array.get(arr, idx);
            if (v instanceof Boolean b) {
                v = b ? 1 : 0;
            } else if (v instanceof Character ch) {
                v = (int) ch;
            } else if (v instanceof Byte b) {
                v = (int) b;
            } else if (v instanceof Short sh) {
                v = (int) sh;
            }
            return Dynamic.box(vm, v, org.objectweb.asm.Type.getType(comp.descriptor()));
        });
        put(c + "putItem(Ljava/lang/Object;ILjava/lang/Object;)V", a -> {
            int idx = i(a[2]);
            if (a[1] instanceof RefArray r) {
                r.data[idx] = a[3];
                return null;
            }
            VClass comp = vm.classOf(a[1]).component;
            org.objectweb.asm.Type t = org.objectweb.asm.Type.getType(comp.descriptor());
            Object v = Dynamic.adapt(vm, a[3], org.objectweb.asm.Type.getObjectType("java/lang/Object"), t);
            switch (comp.primitive) {
                case 'Z' -> ((boolean[]) a[1])[idx] = i(v) != 0;
                case 'B' -> ((byte[]) a[1])[idx] = (byte) i(v);
                case 'C' -> ((char[]) a[1])[idx] = (char) i(v);
                case 'S' -> ((short[]) a[1])[idx] = (short) i(v);
                case 'I' -> ((int[]) a[1])[idx] = i(v);
                case 'J' -> ((long[]) a[1])[idx] = (Long) v;
                case 'F' -> ((float[]) a[1])[idx] = (Float) v;
                default -> ((double[]) a[1])[idx] = (Double) v;
            }
            return null;
        });
        put(c + "newInstance()Ljava/lang/Object;", a -> {
            VClass k = cls(a[0]);
            if (k.isInterface() || k.isArray() || k.isPrimitive() || (k.access & Opcodes.ACC_ABSTRACT) != 0) {
                return null;
            }
            return new VObject(k);
        });
        put(c + "initializeNewInstance(Ljava/lang/Object;)Z", a -> {
            VClass k = cls(a[0]);
            VMethod init = k.methods.get("<init>()V");
            if (init == null) {
                return 0;
            }
            vm.invoke(init, new Object[] {a[1]});
            return 1;
        });
        put(c + "initialize()V", a -> {
            vm.initialize(cls(a[0]));
            return null;
        });
        put(c + "reflection()Lorg/teavm/runtime/reflect/ClassReflectionInfo;", a -> null);
        put(c + "classObject()Ljava/lang/Class;", a -> vm.classObject(cls(a[0])));

        // TeaVM resolves Class.forName against the closed world it compiled; here classes load lazily.
        put("java/lang/Class.forName(Ljava/lang/String;)Ljava/lang/Class;", a -> {
            String name = VM.host(a[0]);
            VClass k = name == null || name.contains("/") ? null : vm.tryLoad(name.replace('.', '/'));
            if (k == null) {
                throw vm.error("java/lang/ClassNotFoundException", name);
            }
            vm.initialize(k);
            return vm.classObject(k);
        });
    }

    private RefArray enumConstants(VClass k) {
        if ((k.access & Opcodes.ACC_ENUM) == 0) {
            return new RefArray(vm.arrayOf(k), 0);
        }
        vm.initialize(k);
        return (RefArray) vm.invoke(k.methods.get("values()[L" + k.name + ";"), new Object[0]);
    }

    // ------------------------------------------------------------------ java.lang.Throwable

    private void throwable() {
        put("java/lang/Throwable.fillInStackTrace()Ljava/lang/Throwable;", a -> {
            VObject t = (VObject) a[0];
            List<VM.Frame> frames = vm.stackSnapshot(0);
            // Drop the frames of the exception's own constructors and fillInStackTrace.
            int skip = 0;
            while (skip < frames.size()) {
                VMethod m = frames.get(skip).method;
                if ((m.name.equals("<init>") || m.name.equals("fillInStackTrace")) && t.cls.isAssignableTo(m.owner)) {
                    skip++;
                } else {
                    break;
                }
            }
            VClass ste = vm.load("java/lang/StackTraceElement");
            RefArray arr = new RefArray(vm.arrayOf(ste), frames.size() - skip);
            for (int k = skip; k < frames.size(); k++) {
                VM.Frame f = frames.get(k);
                VMethod m = f.method;
                int line = m.lines != null && f.pc < m.lines.length ? m.lines[f.pc] : -1;
                arr.data[k - skip] = vm.construct("java/lang/StackTraceElement",
                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V",
                        vm.str(m.owner.javaName()), vm.str(m.name), vm.str(m.owner.sourceFile), line);
            }
            VField field = vm.findField(vm.load("java/lang/Throwable"), "stackTrace");
            t.fields[field.slot] = arr;
            return t;
        });
    }
}
