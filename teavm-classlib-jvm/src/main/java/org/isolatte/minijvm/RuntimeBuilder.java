package org.isolatte.minijvm;

import static org.objectweb.asm.Opcodes.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

/**
 * Builds the boot class path jar that lets miniJVM run with TeaVM's class library as its entire JRE.
 *
 * <pre>
 * rename   OUT_DIR TEAVM_JAR...                      TeaVM's classes, renamed (TeaVMRenamer)
 * assemble OUT_JAR RENAMED_DIR MIXIN_DIR APP_CP CLASSLIB_JAR
 * </pre>
 *
 * {@code assemble} starts from every class of APP_CP (guest support, gap classes, xml-apis, Xerces,
 * the demo) plus the classes miniJVM's C code names, and pulls in TeaVM classes as they are
 * referenced. Each class gets: its mixin merged (src/minijvm-mixins: the fields and methods
 * miniJVM's C code expects, TeaVM backend natives given bodies or bound to miniJVM natives), the
 * rewrites below, invokedynamic desugared, metadata natives baked, version 50 without stack maps.
 */
public final class RuntimeBuilder {
    private static final String PROVIDED = "Ljdk/internal/mixin/MixinProvided;";
    private static final String REPLACE = "Ljdk/internal/mixin/MixinReplace;";

    /** Classes miniJVM's C code loads or looks up by name (global.c, class.c, jvm.c). */
    private static final List<String> REQUIRED = List.of(
            "java/lang/Object", "java/lang/String", "java/lang/StringBuilder", "java/lang/Class", "java/lang/ClassLoader",
            "java/lang/Thread", "java/lang/ThreadGroup", "java/lang/Throwable", "java/lang/StackTraceElement",
            "java/lang/Boolean", "java/lang/Byte", "java/lang/Short", "java/lang/Character", "java/lang/Integer",
            "java/lang/Long", "java/lang/Float", "java/lang/Double", "java/lang/ref/Reference",
            "java/lang/ref/WeakReference", "java/lang/InterruptedException", "java/lang/OutOfMemoryError",
            "java/lang/VirtualMachineError", "java/lang/NoClassDefFoundError", "java/io/EOFException",
            "java/io/IOException", "java/io/FileNotFoundException", "java/lang/ArithmeticException",
            "java/lang/ClassNotFoundException", "java/lang/NullPointerException", "java/lang/NoSuchMethodError",
            "java/lang/NoSuchFieldError", "java/lang/IllegalArgumentException", "java/lang/ClassCastException",
            "java/lang/ArrayIndexOutOfBoundsException", "java/lang/InstantiationException",
            "java/lang/IllegalMonitorStateException", "java/lang/NegativeArraySizeException",
            "java/lang/ArrayStoreException", "java/lang/AbstractMethodError", "java/lang/IllegalAccessError",
            "java/lang/IncompatibleClassChangeError", "java/lang/Cloneable", "java/io/Serializable",
            "sun/misc/Launcher");

    private static final Map<String, String> BOX_PRIMITIVE = Map.of(
            "java/lang/Boolean", "boolean", "java/lang/Byte", "byte", "java/lang/Short", "short",
            "java/lang/Character", "char", "java/lang/Integer", "int", "java/lang/Long", "long",
            "java/lang/Float", "float", "java/lang/Double", "double", "java/lang/Void", "void");

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "rename" -> rename(Path.of(args[1]), List.of(args).subList(2, args.length));
            case "assemble" -> new RuntimeBuilder().assemble(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]),
                    List.of(args[4].split(":")), new File(args[5]));
            default -> throw new IllegalArgumentException(args[0]);
        }
    }

    // ------------------------------------------------------------------ rename

    private static void rename(Path out, List<String> jars) throws IOException {
        int n = 0;
        for (String jar : jars) {
            try (ZipFile zip = new ZipFile(jar)) {
                for (ZipEntry e : Collections.list(zip.entries())) {
                    if (!e.getName().endsWith(".class") || e.getName().startsWith("META-INF/")) {
                        continue;
                    }
                    byte[] bytes;
                    try (InputStream in = zip.getInputStream(e)) {
                        bytes = in.readAllBytes();
                    }
                    ClassNode node = TeaVMRenamer.rename(bytes);
                    if (node == null) {
                        continue;
                    }
                    Path target = out.resolve(node.name + ".class");
                    if (Files.exists(target)) {
                        continue; // first jar wins
                    }
                    Files.createDirectories(target.getParent());
                    ClassWriter w = new ClassWriter(0);
                    node.accept(w);
                    Files.write(target, w.toByteArray());
                    n++;
                }
            }
        }
        System.out.println("renamed " + n + " classes -> " + out);
    }

    // ------------------------------------------------------------------ assemble

    private final Map<String, byte[]> appClasses = new LinkedHashMap<>();
    private final Map<String, byte[]> appResources = new TreeMap<>();
    private final Map<String, byte[]> mixins = new HashMap<>();
    private final Map<String, ClassNode> output = new TreeMap<>();
    private final Deque<String> queue = new ArrayDeque<>();
    private final Set<String> seen = new LinkedHashSet<>();
    private final List<String> missing = new ArrayList<>();
    private final IndyDesugar indy = new IndyDesugar();
    private Path renamed;
    private MetadataBaker baker;
    private int mixinCount;
    private int lambdaCount;

    private void assemble(Path outJar, Path renamedDir, Path mixinDir, List<String> appCp, File classlib) throws Exception {
        renamed = renamedDir;
        baker = new MetadataBaker(List.of(classlib));
        for (String e : appCp) {
            readEntry(Path.of(e));
        }
        try (Stream<Path> s = Files.walk(mixinDir)) {
            for (Path p : s.filter(p -> p.toString().endsWith(".class")).toList()) {
                String name = mixinDir.relativize(p).toString().replace(File.separatorChar, '/');
                name = name.substring(0, name.length() - 6);
                if (!name.startsWith("jdk/internal/mixin/")) {
                    mixins.put(name, Files.readAllBytes(p));
                }
            }
        }
        for (String name : appClasses.keySet()) {
            enqueue(name);
        }
        for (String name : mixins.keySet()) {
            if (!Files.exists(renamed.resolve(name + ".class"))) {
                enqueue(name); // mixin helper class
            }
        }
        REQUIRED.forEach(this::enqueue);
        while (!queue.isEmpty()) {
            process(queue.poll());
        }
        for (ClassNode c : baker.generatedClasses()) {
            add(c);
        }
        while (!queue.isEmpty()) {
            process(queue.poll());
        }
        write(outJar);
        System.out.printf("assembled %d classes (%d mixins, %d lambda classes), %d resources -> %s%n",
                output.size(), mixinCount, lambdaCount, appResources.size(), outJar);
        baker.baked.forEach(b -> System.out.println("  metadata " + b));
        missing.removeIf(output::containsKey);
        Collections.sort(missing);
        Files.write(outJar.resolveSibling(outJar.getFileName() + ".missing.txt"), missing);
        System.out.println("  " + missing.size() + " referenced classes not available (listed in "
                + outJar.getFileName() + ".missing.txt)");
    }

    private void readEntry(Path entry) throws IOException {
        if (Files.isDirectory(entry)) {
            try (Stream<Path> s = Files.walk(entry)) {
                for (Path p : s.filter(Files::isRegularFile).toList()) {
                    String name = entry.relativize(p).toString().replace(File.separatorChar, '/');
                    putApp(name, Files.readAllBytes(p));
                }
            }
        } else {
            try (ZipFile zip = new ZipFile(entry.toFile())) {
                for (ZipEntry e : Collections.list(zip.entries())) {
                    if (!e.isDirectory()) {
                        try (InputStream in = zip.getInputStream(e)) {
                            putApp(e.getName(), in.readAllBytes());
                        }
                    }
                }
            }
        }
    }

    private void putApp(String name, byte[] bytes) {
        if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
            appClasses.putIfAbsent(name.substring(0, name.length() - 6), bytes);
        } else if (!name.equals("META-INF/MANIFEST.MF") && !name.endsWith(".SF") && !name.endsWith(".RSA")) {
            appResources.putIfAbsent(name, bytes);
        }
    }

    private void enqueue(String name) {
        if (seen.add(name)) {
            queue.add(name);
        }
    }

    private byte[] bytesOf(String name) throws IOException {
        byte[] b = appClasses.get(name);
        if (b != null) {
            return b;
        }
        Path p = renamed.resolve(name + ".class");
        if (Files.exists(p)) {
            return Files.readAllBytes(p);
        }
        return mixins.get(name);
    }

    private void process(String name) throws IOException {
        if (name.equals("sun/misc/Launcher")) {
            add(launcher());
            return;
        }
        byte[] bytes = bytesOf(name);
        if (bytes == null) {
            missing.add(name);
            return;
        }
        ClassNode node = read(bytes);
        byte[] mixin = mixins.get(name);
        if (mixin != null && mixin != bytes) {
            merge(node, read(mixin));
            mixinCount++;
        }
        rewrite(node);
        privateCalls(node);
        for (ClassNode lambda : indy.desugar(node)) {
            lambdaCount++;
            privateCalls(lambda); // lambda bodies are private methods of the host class
            add(lambda);
        }
        baker.bake(node);
        add(node);
    }

    private void add(ClassNode node) {
        node.version = V1_6;
        output.put(node.name, node);
        seen.add(node.name);
        for (String ref : references(node)) {
            enqueue(ref);
        }
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
        return node;
    }

    private void write(Path outJar) throws IOException {
        Files.createDirectories(outJar.toAbsolutePath().getParent());
        try (OutputStream os = Files.newOutputStream(outJar); JarOutputStream jar = new JarOutputStream(os)) {
            for (ClassNode node : output.values()) {
                ClassWriter w = new ClassWriter(ClassWriter.COMPUTE_MAXS);
                node.accept(w);
                jar.putNextEntry(new JarEntry(node.name + ".class"));
                jar.write(w.toByteArray());
                jar.closeEntry();
            }
            for (Map.Entry<String, byte[]> r : appResources.entrySet()) {
                jar.putNextEntry(new JarEntry(r.getKey()));
                jar.write(r.getValue());
                jar.closeEntry();
            }
        }
    }

    // ------------------------------------------------------------------ mixins

    private static boolean has(List<AnnotationNode> list, String desc) {
        if (list != null) {
            for (AnnotationNode a : list) {
                if (a.desc.equals(desc)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Adds the mixin's fields and methods to the TeaVM class. {@code @MixinProvided} members only
     * exist so the mixin compiles; {@code @MixinReplace} replaces TeaVM's member (e.g. a TeaVM
     * native by a body, or a TeaVM method by a miniJVM native). A mixin constructor that TeaVM
     * already has (javac's default constructor) is ignored.
     */
    private static void merge(ClassNode base, ClassNode mixin) {
        for (FieldNode f : mixin.fields) {
            if (has(f.invisibleAnnotations, PROVIDED)) {
                continue;
            }
            for (FieldNode existing : base.fields) {
                if (existing.name.equals(f.name) && existing.desc.equals(f.desc)) {
                    throw new IllegalStateException(base.name + "." + f.name + " already exists in TeaVM");
                }
            }
            base.fields.add(f);
        }
        for (MethodNode m : mixin.methods) {
            if (has(m.invisibleAnnotations, PROVIDED)) {
                continue;
            }
            MethodNode existing = null;
            for (MethodNode b : base.methods) {
                if (b.name.equals(m.name) && b.desc.equals(m.desc)) {
                    existing = b;
                }
            }
            if (has(m.invisibleAnnotations, REPLACE)) {
                if (existing == null) {
                    throw new IllegalStateException(base.name + "." + m.name + m.desc + ": nothing to replace");
                }
                base.methods.set(base.methods.indexOf(existing), m);
            } else if (existing == null) {
                base.methods.add(m);
            } else if (!m.name.equals("<init>")) {
                throw new IllegalStateException(base.name + "." + m.name + m.desc
                        + " already exists in TeaVM; annotate it @MixinProvided or @MixinReplace");
            }
        }
    }

    // ------------------------------------------------------------------ rewrites

    private static void rewrite(ClassNode node) {
        if (has(node.visibleAnnotations, "Lorg/teavm/metaprogramming/CompileTime;")) {
            // Metaprogramming bodies run inside TeaVM's compiler; only their @Meta stubs (replaced
            // by mixins) are called at run time.
            node.methods.removeIf(m -> !m.name.equals("<init>") && !has(m.invisibleAnnotations, REPLACE));
        }
        if (node.name.equals("java/lang/Class")) {
            node.fields.removeIf(f -> f.name.equals("classInfo"));
        }
        if (node.name.equals("java/lang/Thread")) {
            // miniJVM names its threads through a char[] field "name"; TeaVM's "name" is a String.
            // Two fields may share a name when their descriptors differ, but Java source cannot say so.
            node.fields.add(new FieldNode(ACC_PRIVATE, "name", "[C", null, null));
        }
        if (node.name.equals("java/lang/Throwable")) {
            for (FieldNode f : node.fields) {
                if (f.name.equals("message")) {
                    f.name = "detailMessage"; // miniJVM prints uncaught exceptions from this field
                }
            }
        }
        for (MethodNode m : node.methods) {
            if (m.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn : m.instructions.toArray()) {
                if (insn instanceof FieldInsnNode fi) {
                    rewriteField(node, m, fi);
                }
            }
        }
    }

    private static void rewriteField(ClassNode node, MethodNode m, FieldInsnNode fi) {
        InsnList code = m.instructions;
        if (fi.owner.equals("java/lang/System") && fi.getOpcode() == GETSTATIC
                && (fi.name.equals("out") || fi.name.equals("err") || fi.name.equals("in"))) {
            // TeaVM's System has out()/err()/in() methods; its compiler rewrites the field reads.
            code.set(fi, new MethodInsnNode(INVOKESTATIC, "java/lang/System", fi.name, "()" + fi.desc, false));
        } else if (fi.owner.equals("java/lang/Class") && fi.name.equals("classInfo")) {
            // A Class is its own ClassInfo (see TeaVMRenamer).
            if (fi.getOpcode() == GETFIELD) {
                code.remove(fi);
            } else {
                code.set(fi, new InsnNode(POP2));
            }
        } else if (fi.owner.equals("java/lang/Throwable") && fi.name.equals("message")) {
            fi.name = "detailMessage";
        } else if (fi.getOpcode() == GETSTATIC && fi.name.equals("TYPE") && fi.owner.equals(node.name)
                && m.name.equals("<clinit>") && BOX_PRIMITIVE.containsKey(node.name)) {
            // javac compiles int.class to Integer.TYPE, so TeaVM's Integer.<clinit> reads its own
            // field; TeaVM's compiler intrinsifies it. Here it asks miniJVM for the primitive class.
            InsnList r = new InsnList();
            r.add(new LdcInsnNode(BOX_PRIMITIVE.get(node.name)));
            r.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Class", "vm$getPrimitiveClass",
                    "(Ljava/lang/String;)Ljava/lang/Class;", false));
            code.insertBefore(fi, r);
            code.remove(fi);
        }
    }

    private final Map<String, Set<String>> privateMethods = new HashMap<>();

    /**
     * Since Java 11 (nestmates, JEP 181) javac calls private methods with invokevirtual or
     * invokeinterface. miniJVM implements the older rule (private methods through invokespecial
     * only) and throws IllegalAccessError, so such calls are rewritten as javac 8 would emit them.
     */
    private void privateCalls(ClassNode node) throws IOException {
        for (MethodNode m : node.methods) {
            if (m.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn : m.instructions) {
                if (insn instanceof MethodInsnNode mi && (mi.getOpcode() == INVOKEVIRTUAL || mi.getOpcode() == INVOKEINTERFACE)
                        && !mi.owner.startsWith("[") && privateMethodsOf(mi.owner, node).contains(mi.name + mi.desc)) {
                    mi.setOpcode(INVOKESPECIAL);
                }
            }
        }
    }

    private Set<String> privateMethodsOf(String owner, ClassNode current) throws IOException {
        Set<String> result = privateMethods.get(owner);
        if (result == null) {
            result = new java.util.HashSet<>();
            List<byte[]> sources = new ArrayList<>();
            byte[] b = bytesOf(owner);
            if (b != null) {
                sources.add(b);
            }
            if (mixins.containsKey(owner)) {
                sources.add(mixins.get(owner));
            }
            for (byte[] src : sources) {
                ClassNode n = new ClassNode();
                new ClassReader(src).accept(n, ClassReader.SKIP_CODE);
                for (MethodNode mn : n.methods) {
                    if ((mn.access & ACC_PRIVATE) != 0) {
                        result.add(mn.name + mn.desc);
                    }
                }
            }
            privateMethods.put(owner, result);
        }
        return result;
    }

    /** miniJVM's sun.misc.Launcher contract: everything is on the boot class path. */
    private static ClassNode launcher() {
        ClassNode c = new ClassNode();
        c.access = ACC_PUBLIC | ACC_SUPER;
        c.name = "sun/misc/Launcher";
        c.superName = "java/lang/Object";
        MethodNode get = new MethodNode(ACC_PUBLIC | ACC_STATIC, "getSystemClassLoader", "()Ljava/lang/ClassLoader;", null, null);
        get.instructions.add(new InsnNode(ACONST_NULL));
        get.instructions.add(new InsnNode(ARETURN));
        c.methods.add(get);
        MethodNode load = new MethodNode(ACC_PUBLIC | ACC_STATIC, "loadClass",
                "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;", null, null);
        load.instructions.add(new VarInsnNode(ALOAD, 0));
        load.instructions.add(new InsnNode(ICONST_0));
        load.instructions.add(new InsnNode(ACONST_NULL));
        load.instructions.add(new MethodInsnNode(INVOKESTATIC, "java/lang/Class", "vm$forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false));
        load.instructions.add(new InsnNode(ARETURN));
        c.methods.add(load);
        return c;
    }

    // ------------------------------------------------------------------ closure

    private static Set<String> references(ClassNode node) {
        Set<String> refs = new LinkedHashSet<>();
        if (node.superName != null) {
            refs.add(node.superName);
        }
        refs.addAll(node.interfaces);
        for (FieldNode f : node.fields) {
            addDesc(refs, Type.getType(f.desc));
        }
        for (MethodNode m : node.methods) {
            addDesc(refs, Type.getMethodType(m.desc));
            if (m.tryCatchBlocks != null) {
                for (TryCatchBlockNode t : m.tryCatchBlocks) {
                    if (t.type != null) {
                        refs.add(t.type);
                    }
                }
            }
            if (m.instructions == null) {
                continue;
            }
            for (AbstractInsnNode insn : m.instructions) {
                if (insn instanceof TypeInsnNode t) {
                    addDesc(refs, t.desc.startsWith("[") ? Type.getType(t.desc) : Type.getObjectType(t.desc));
                } else if (insn instanceof FieldInsnNode f) {
                    refs.add(f.owner);
                    addDesc(refs, Type.getType(f.desc));
                } else if (insn instanceof MethodInsnNode mi) {
                    if (!mi.owner.startsWith("[")) {
                        refs.add(mi.owner);
                    }
                    addDesc(refs, Type.getMethodType(mi.desc));
                } else if (insn instanceof LdcInsnNode l && l.cst instanceof Type t) {
                    addDesc(refs, t);
                } else if (insn instanceof MultiANewArrayInsnNode ma) {
                    addDesc(refs, Type.getType(ma.desc));
                }
            }
        }
        refs.remove(node.name);
        return refs;
    }

    private static void addDesc(Set<String> refs, Type t) {
        switch (t.getSort()) {
            case Type.ARRAY -> addDesc(refs, t.getElementType());
            case Type.OBJECT -> refs.add(t.getInternalName());
            case Type.METHOD -> {
                addDesc(refs, t.getReturnType());
                for (Type a : t.getArgumentTypes()) {
                    addDesc(refs, a);
                }
            }
            default -> {
            }
        }
    }
}
