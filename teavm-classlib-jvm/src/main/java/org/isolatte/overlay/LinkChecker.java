package org.isolatte.overlay;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * Static link check of an overlay against the running JDK's java.base.
 *
 * <p>Reports (1) references made by overlay classes that resolve neither in the overlay nor in
 * OpenJDK, (2) references made by the remaining OpenJDK java.base classes into overlay classes that
 * the TeaVM implementation does not provide, (3) the same for client jars (e.g. Xerces), and
 * (4) overlay native methods, which have no JNI implementation on HotSpot.
 *
 * <p>It does not see JNI field access from libjava, reflection, {@code Unsafe} offsets or access
 * modifiers; those only show up at run time.
 *
 * <p>Usage: {@code LinkChecker <overlayDir> [client.jar|dir]...}
 */
public final class LinkChecker {
    static final class Info {
        String name;
        String superName;
        String[] interfaces = new String[0];
        final Set<String> methods = new HashSet<>();
        final Map<String, Boolean> polymorphic = new HashMap<>();
        final Set<String> fields = new HashSet<>();
        final List<String> natives = new ArrayList<>();
    }

    private final Map<String, Info> universe = new HashMap<>();
    private final Set<String> overlay = new HashSet<>();
    // missing symbol -> referencing classes
    private final Map<String, Set<String>> missing = new TreeMap<>();

    public static void main(String[] args) throws IOException {
        new LinkChecker().run(args);
    }

    private void run(String[] args) throws IOException {
        FileSystem jrt = FileSystems.getFileSystem(URI.create("jrt:/"));
        Path base = jrt.getPath("/modules/java.base");
        List<Path> jdkFiles;
        try (Stream<Path> s = Files.walk(base)) {
            jdkFiles = s.filter(p -> p.toString().endsWith(".class")).toList();
        }
        for (Path p : jdkFiles) {
            index(Files.readAllBytes(p), false);
        }
        Path overlayDir = Path.of(args[0]);
        List<Path> overlayFiles;
        try (Stream<Path> s = Files.walk(overlayDir)) {
            overlayFiles = s.filter(p -> p.toString().endsWith(".class")).toList();
        }
        for (Path p : overlayFiles) {
            index(Files.readAllBytes(p), true);
        }

        for (Path p : overlayFiles) {
            scan(Files.readAllBytes(p), "overlay", false);
        }
        for (Path p : jdkFiles) {
            byte[] b = Files.readAllBytes(p);
            if (!overlay.contains(new ClassReader(b).getClassName())) {
                scan(b, "openjdk", true);
            }
        }
        List<byte[]> clients = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            Path client = Path.of(args[i]);
            if (Files.isDirectory(client)) {
                try (Stream<Path> s = Files.walk(client)) {
                    for (Path p : s.filter(q -> q.toString().endsWith(".class")).toList()) {
                        clients.add(Files.readAllBytes(p));
                    }
                }
            } else {
                try (JarFile jar = new JarFile(client.toFile())) {
                    for (JarEntry e : jar.stream().toList()) {
                        if (e.getName().endsWith(".class") && !e.getName().startsWith("META-INF/")) {
                            try (InputStream in = jar.getInputStream(e)) {
                                clients.add(in.readAllBytes());
                            }
                        }
                    }
                }
            }
        }
        for (byte[] b : clients) {
            index(b, false);
        }
        for (byte[] b : clients) {
            scan(b, "client", true);
        }

        System.out.println("overlay classes: " + overlay.size());
        Map<String, Integer> byOrigin = new TreeMap<>();
        for (Map.Entry<String, Set<String>> e : missing.entrySet()) {
            byOrigin.merge(e.getKey().substring(0, e.getKey().indexOf(' ')), 1, Integer::sum);
        }
        System.out.println("unresolved symbols by referrer: " + byOrigin);
        for (Map.Entry<String, Set<String>> e : missing.entrySet()) {
            Set<String> refs = e.getValue();
            String sample = String.join(", ", refs.stream().limit(3).toList());
            System.out.println("  " + e.getKey() + "  <- " + refs.size() + " class(es): " + sample
                    + (refs.size() > 3 ? ", ..." : ""));
        }
        TreeSet<String> natives = new TreeSet<>();
        for (String c : overlay) {
            for (String n : universe.get(c).natives) {
                natives.add(c + "." + n);
            }
        }
        // HotSpot binds a boot class's natives to libjava's exported Java_<class>_<method> symbols.
        String libjava = new String(Files.readAllBytes(Path.of(System.getProperty("java.home"), "lib",
                System.mapLibraryName("java"))), java.nio.charset.StandardCharsets.ISO_8859_1);
        System.out.println("overlay native methods: " + natives.size());
        for (String n : natives) {
            String cls = n.substring(0, n.indexOf('.'));
            String method = n.substring(n.indexOf('.') + 1, n.indexOf('('));
            String symbol = "Java_" + cls.replace("_", "_1").replace('/', '_') + "_" + method.replace("_", "_1");
            boolean bound = libjava.contains(symbol + "\0");
            System.out.println("  " + n + (bound ? "  -> libjava " + symbol : "  UNBOUND (no libjava symbol)"));
        }
    }

    private void index(byte[] bytes, boolean isOverlay) {
        Info info = new Info();
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int v, int access, String name, String sig, String superName, String[] itfs) {
                info.name = name;
                info.superName = superName;
                info.interfaces = itfs == null ? new String[0] : itfs;
            }

            @Override
            public FieldVisitor visitField(int access, String name, String desc, String sig, Object value) {
                info.fields.add(name + ":" + desc);
                return null;
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                info.methods.add(name + desc);
                if ((access & Opcodes.ACC_NATIVE) != 0) {
                    info.natives.add(name + desc);
                    if ((access & Opcodes.ACC_VARARGS) != 0) {
                        info.polymorphic.put(name, true);
                    }
                }
                return null;
            }
        }, ClassReader.SKIP_CODE);
        if (isOverlay) {
            overlay.add(info.name);
            universe.put(info.name, info);
        } else {
            universe.putIfAbsent(info.name, info);
        }
    }

    private void scan(byte[] bytes, String origin, boolean onlyIntoOverlay) {
        ClassReader reader = new ClassReader(bytes);
        String self = reader.getClassName();
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int v, int access, String name, String sig, String superName, String[] itfs) {
                checkClass(superName);
                if (itfs != null) {
                    for (String i : itfs) {
                        checkClass(i);
                    }
                }
            }

            private void checkClass(String owner) {
                if (owner == null) {
                    return;
                }
                String elem = element(owner);
                if (elem == null || (onlyIntoOverlay && !overlay.contains(elem))) {
                    return;
                }
                if (!universe.containsKey(elem)) {
                    report(origin + " class " + elem, self);
                }
            }

            private void checkDesc(String desc) {
                for (Type t : Type.getArgumentTypes(desc)) {
                    checkType(t);
                }
                checkType(Type.getReturnType(desc));
            }

            private void checkType(Type t) {
                if (t.getSort() == Type.ARRAY) {
                    t = t.getElementType();
                }
                if (t.getSort() == Type.OBJECT) {
                    checkClass(t.getInternalName());
                }
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                checkDesc(desc);
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitTypeInsn(int opcode, String type) {
                        checkClass(type);
                    }

                    @Override
                    public void visitFieldInsn(int opcode, String owner, String fname, String fdesc) {
                        if (owner.startsWith("[")) {
                            return;
                        }
                        if (onlyIntoOverlay && !overlay.contains(owner)) {
                            return;
                        }
                        checkClass(owner);
                        checkType(Type.getType(fdesc));
                        if (universe.containsKey(owner) && !hasField(owner, fname + ":" + fdesc)) {
                            report(origin + " field " + owner + "." + fname + ":" + fdesc, self);
                        }
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String mname, String mdesc, boolean itf) {
                        checkMethod(owner, mname, mdesc);
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof Type t && t.getSort() != Type.METHOD) {
                            checkType(t);
                        } else if (value instanceof Handle h) {
                            checkMethod(h.getOwner(), h.getName(), h.getDesc());
                        }
                    }

                    @Override
                    public void visitInvokeDynamicInsn(String n, String d, Handle bsm, Object... args) {
                        for (Object a : args) {
                            if (a instanceof Handle h && h.getTag() >= Opcodes.H_INVOKEVIRTUAL) {
                                checkMethod(h.getOwner(), h.getName(), h.getDesc());
                            }
                        }
                    }

                    private void checkMethod(String owner, String mname, String mdesc) {
                        if (owner.startsWith("[")) {
                            return;
                        }
                        if (onlyIntoOverlay && !overlay.contains(owner)) {
                            return;
                        }
                        checkClass(owner);
                        checkDesc(mdesc);
                        if (universe.containsKey(owner) && !hasMethod(owner, mname, mdesc)) {
                            report(origin + " method " + owner + "." + mname + mdesc, self);
                        }
                    }
                };
            }
        }, 0);
    }

    private static String element(String internal) {
        if (internal.startsWith("[")) {
            Type t = Type.getType(internal).getElementType();
            return t.getSort() == Type.OBJECT ? t.getInternalName() : null;
        }
        return internal;
    }

    private boolean hasField(String owner, String key) {
        for (String c = owner; c != null; ) {
            Info info = universe.get(c);
            if (info == null) {
                return false;
            }
            if (info.fields.contains(key) || anyInterfaceHasField(info, key)) {
                return true;
            }
            c = info.superName;
        }
        return false;
    }

    private boolean anyInterfaceHasField(Info info, String key) {
        for (String i : info.interfaces) {
            Info ii = universe.get(i);
            if (ii != null && (ii.fields.contains(key) || anyInterfaceHasField(ii, key))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasMethod(String owner, String name, String desc) {
        Set<String> seen = new HashSet<>();
        List<String> queue = new ArrayList<>(List.of(owner));
        while (!queue.isEmpty()) {
            String c = queue.remove(queue.size() - 1);
            Info info = universe.get(c);
            if (info == null || !seen.add(c)) {
                continue;
            }
            if (info.methods.contains(name + desc) || info.polymorphic.containsKey(name)) {
                return true;
            }
            if (info.superName != null) {
                queue.add(info.superName);
            }
            queue.addAll(List.of(info.interfaces));
        }
        return false;
    }

    private void report(String symbol, String from) {
        missing.computeIfAbsent(symbol, k -> new TreeSet<>()).add(from);
    }

    private LinkChecker() {
    }
}
