package org.isolatte.overlay;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

/**
 * Builds a {@code --patch-module java.base=<dir>} overlay out of TeaVM's class library.
 *
 * <p>TeaVM ships its JRE as {@code org.teavm.classlib.java.x.TName} and substitutes it for
 * {@code java.x.Name} at compile time (see {@code ClasslibSubstitutionPolicy}: package prefix
 * {@code org.teavm.classlib.}, simple-name prefix {@code T} on the top-level class only). This tool
 * applies the same renaming to the bytecode, so the classes can be loaded by HotSpot as real
 * {@code java.*} classes instead of the OpenJDK implementations.
 *
 * <p>Usage: {@code OverlayBuilder <classlib.jar> <core.jar> <outDir> <selector>...}. A selector
 * ending in {@code /} selects one package (e.g. {@code java/io/}); {@code java/lang/**} selects a
 * package tree; otherwise it selects one class and its nested classes (e.g. {@code java/io/File}). A
 * selector prefixed with {@code !} excludes what it matches.
 * References from selected classes to unselected TeaVM classes are mapped to the OpenJDK class of the
 * same name, which is what TeaVM does when it links against its own library.
 */
public final class OverlayBuilder {
    static final String PREFIX = "org/teavm/classlib/";
    /** TeaVM's virtual file system API (teavm-core), which TeaVM's java.io is written against. */
    static final String FS = "org/teavm/runtime/fs/";
    /**
     * HotSpot only accepts packages that java.base already has before the module system is up
     * ("A non-java.base package was loaded prior to module system initialization"), and java.io.File
     * is used during boot. So the API moves into the existing, unexported jdk.internal.io package.
     */
    static final String FS_TARGET = "jdk/internal/io/";

    /**
     * TeaVM-private classes that java.io refers to and that have an OpenJDK equivalent. Their TeaVM
     * packages (e.g. java.nio.charset.impl) do not exist in java.base, and HotSpot rejects new packages
     * loaded during boot, when System.out (a TeaVM PrintStream) is created.
     */
    static final Map<String, String> SUBSTITUTE = Map.of(
            PREFIX + "java/nio/charset/impl/TUTF8Charset", "sun/nio/cs/UTF_8");

    /** TeaVM-only static methods of java.lang.System, redirected to a helper. */
    static final Map<String, String> SYSTEM_REDIRECT = Map.of("getTempDir", "jdk/internal/io/TeaVMSupport");

    /** TeaVM's substitution rule, in internal-name form. */
    static String map(String internalName) {
        String substitute = SUBSTITUTE.get(internalName);
        if (substitute != null) {
            return substitute;
        }
        if (internalName.startsWith(FS)) {
            return FS_TARGET + internalName.substring(internalName.lastIndexOf('/') + 1);
        }
        if (!internalName.startsWith(PREFIX + "java/")) {
            return internalName;
        }
        String rest = internalName.substring(PREFIX.length());
        int slash = rest.lastIndexOf('/');
        String pkg = rest.substring(0, slash + 1);
        String simple = rest.substring(slash + 1);
        if (!simple.startsWith("T")) {
            return internalName; // e.g. org/teavm/classlib/java/lang/ClassGenerator: TeaVM compiler plugin
        }
        return pkg + simple.substring(1);
    }

    static boolean selected(String mapped, List<String> selectors) {
        for (String s : selectors) {
            if (s.startsWith("!") && matches(mapped, s.substring(1))) {
                return false;
            }
        }
        for (String s : selectors) {
            if (!s.startsWith("!") && matches(mapped, s)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matches(String mapped, String s) {
        if (s.endsWith("/**")) {
            return mapped.startsWith(s.substring(0, s.length() - 2));
        }
        if (s.endsWith("/")) {
            return mapped.startsWith(s) && mapped.indexOf('/', s.length()) < 0;
        }
        return mapped.equals(s) || mapped.startsWith(s + "$");
    }

    public static void main(String[] args) throws IOException {
        Path classlib = Path.of(args[0]);
        Path core = Path.of(args[1]);
        Path out = Path.of(args[2]);
        List<String> selectors = List.of(args).subList(3, args.length);
        Remapper remapper = new Remapper() {
            @Override
            public String map(String internalName) {
                return OverlayBuilder.map(internalName);
            }
        };

        TreeSet<String> written = new TreeSet<>();
        try (JarFile jar = new JarFile(classlib.toFile())) {
            for (JarEntry e : list(jar)) {
                String name = e.getName();
                if (!name.endsWith(".class") || !name.startsWith(PREFIX + "java/")) {
                    continue;
                }
                String internal = name.substring(0, name.length() - 6);
                String mapped = map(internal);
                if (mapped.equals(internal) || !selected(mapped, selectors)) {
                    continue;
                }
                byte[] bytes = remap(jar, e, remapper);
                write(out, mapped, bytes);
                written.add(mapped);
            }
        }
        // The file system API must live in java.base: a named module cannot link to the unnamed module.
        try (JarFile jar = new JarFile(core.toFile())) {
            for (JarEntry e : list(jar)) {
                String name = e.getName();
                if (name.startsWith(FS) && name.endsWith(".class") && !name.contains("Transformer")) {
                    String mapped = map(name.substring(0, name.length() - 6));
                    write(out, mapped, remap(jar, e, remapper));
                    written.add(mapped);
                }
            }
        }
        Files.write(out.resolveSibling(out.getFileName() + ".classes.txt"), written);
        System.out.println("overlay: " + written.size() + " classes -> " + out);
    }

    private static List<JarEntry> list(JarFile jar) {
        List<JarEntry> entries = new ArrayList<>();
        jar.stream().forEach(entries::add);
        return entries;
    }

    private static byte[] remap(JarFile jar, JarEntry e, Remapper remapper) throws IOException {
        try (InputStream in = jar.getInputStream(e)) {
            ClassReader reader = new ClassReader(in);
            ClassWriter writer = new ClassWriter(0);
            ClassVisitor redirect = new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                    return new MethodVisitor(Opcodes.ASM9, super.visitMethod(access, name, desc, sig, ex)) {
                        @Override
                        public void visitMethodInsn(int op, String owner, String mname, String mdesc, boolean itf) {
                            String target = owner.equals("java/lang/System") ? SYSTEM_REDIRECT.get(mname) : null;
                            super.visitMethodInsn(op, target != null ? target : owner, mname, mdesc, itf);
                        }
                    };
                }
            };
            reader.accept(new ClassRemapper(redirect, remapper), 0);
            return writer.toByteArray();
        }
    }

    private static void write(Path out, String internal, byte[] bytes) throws IOException {
        Path file = out.resolve(internal + ".class");
        Files.createDirectories(file.getParent());
        Files.write(file, bytes);
    }
}
