package org.isolatte.vm;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Finds guest class files and applies TeaVM's class library substitution to them, the way TeaVM's
 * compiler does ({@code ClasslibSubstitutionPolicy} + {@code ClassRefsRenamer}):
 * <ul>
 * <li>{@code org.teavm.classlib.java.x.TName} becomes {@code java.x.Name} (the {@code T} is dropped
 *     from the top-level simple name only), in every class loaded, so all references agree;</li>
 * <li>{@code @Superclass("")} removes the superclass ({@code TObject} is the root);</li>
 * <li>{@code @Rename("n")} renames a method, replacing a method of the same descriptor;</li>
 * <li>{@code @Remove} drops a method.</li>
 * </ul>
 * There is no fallback to OpenJDK: a guest {@code java.*} class either comes from TeaVM's class
 * library or does not exist.
 */
final class Loader {
    static final String PREFIX = "org/teavm/classlib/";
    private static final String RENAME = "Lorg/teavm/interop/Rename;";
    private static final String SUPERCLASS = "Lorg/teavm/interop/Superclass;";
    private static final String REMOVE = "Lorg/teavm/interop/Remove;";

    /** One class path entry: a jar or a directory. */
    private interface Source {
        byte[] find(String path) throws IOException;
    }

    private final List<Source> sources = new ArrayList<>();
    private final List<String> sourceNames = new ArrayList<>();
    final Remapper remapper = new Remapper() {
        @Override
        public String map(String internalName) {
            return Loader.map(internalName);
        }
    };

    void add(Path entry) {
        sourceNames.add(entry.toString());
        if (Files.isDirectory(entry)) {
            Path base = entry.toAbsolutePath().normalize();
            sources.add(path -> {
                if (!isPlainPath(path)) {
                    return null;
                }
                Path p = base.resolve(path).normalize();
                return p.startsWith(base) && Files.isRegularFile(p) ? Files.readAllBytes(p) : null;
            });
        } else {
            try {
                ZipFile zip = new ZipFile(entry.toFile());
                sources.add(path -> {
                    ZipEntry e = zip.getEntry(path);
                    if (e == null) {
                        return null;
                    }
                    try (InputStream in = zip.getInputStream(e)) {
                        return in.readAllBytes();
                    }
                });
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    /**
     * Guest-supplied names (resources, Class.forName) must not leave a class path directory: no
     * absolute paths and no empty, "." or ".." segments. Jar entries are looked up by exact name.
     */
    static boolean isPlainPath(String path) {
        if (path.isEmpty() || path.startsWith("/") || path.indexOf('\\') >= 0 || path.indexOf('\0') >= 0) {
            return false;
        }
        for (String segment : path.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                return false;
            }
        }
        return true;
    }

    /** TeaVM's substitution rule, in internal-name form. */
    static String map(String internalName) {
        if (!internalName.startsWith(PREFIX + "java/")) {
            return internalName;
        }
        String rest = internalName.substring(PREFIX.length());
        int slash = rest.lastIndexOf('/');
        String simple = rest.substring(slash + 1);
        if (!simple.startsWith("T")) {
            return internalName; // e.g. org/teavm/classlib/java/lang/ClassGenerator: compiler plugin
        }
        return rest.substring(0, slash + 1) + simple.substring(1);
    }

    /** The class file a guest class name comes from: TeaVM's for java.*, otherwise its own name. */
    private static String fileFor(String guestName) {
        if (guestName.startsWith("java/")) {
            int slash = guestName.lastIndexOf('/');
            return PREFIX + guestName.substring(0, slash + 1) + "T" + guestName.substring(slash + 1) + ".class";
        }
        return guestName + ".class";
    }

    /** The renamed class, or null when no class path entry has it. */
    ClassNode load(String guestName) {
        byte[] bytes = find(fileFor(guestName));
        if (bytes == null && guestName.startsWith("java/")) {
            // A java.* class TeaVM does not have: only a gap class from the guest class path
            // (work/vm-gaps) can provide it; there is no OpenJDK class library on it.
            bytes = find(guestName + ".class");
        }
        if (bytes == null) {
            return null;
        }
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(new ClassRemapper(node, remapper), ClassReader.EXPAND_FRAMES);
        if (!node.name.equals(guestName)) {
            return null; // e.g. java/lang/TFoo asked as java/lang/Foo where TFoo is not a T-class
        }
        applyAnnotations(node);
        return node;
    }

    private byte[] find(String file) {
        try {
            for (Source s : sources) {
                byte[] bytes = s.find(file);
                if (bytes != null) {
                    return bytes;
                }
            }
            return null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A resource from the class path, unrenamed (guest resource lookups go through the VFS instead). */
    byte[] resource(String path) {
        try {
            for (Source s : sources) {
                byte[] b = s.find(path);
                if (b != null) {
                    return b;
                }
            }
            return null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void applyAnnotations(ClassNode node) {
        AnnotationNode sup = find(node.invisibleAnnotations, SUPERCLASS);
        if (sup == null) {
            sup = find(node.visibleAnnotations, SUPERCLASS);
        }
        if (sup != null) {
            String parent = (String) sup.values.get(1);
            node.superName = parent.isEmpty() ? null : map(parent.replace('.', '/'));
        }
        if (node.name.equals(node.superName)) {
            node.superName = null;
        }
        node.interfaces.removeIf(i -> i.equals(node.name));
        if (node.name.equals("java/lang/Object")) {
            node.superName = null;
        }

        Map<String, MethodNode> methods = new LinkedHashMap<>();
        Map<String, Boolean> renamed = new HashMap<>();
        for (MethodNode m : node.methods) {
            if (has(m, REMOVE)) {
                continue;
            }
            AnnotationNode r = find(m.invisibleAnnotations, RENAME);
            if (r == null) {
                r = find(m.visibleAnnotations, RENAME);
            }
            if (r != null) {
                m.name = (String) r.values.get(1);
            }
            String key = m.name + m.desc;
            // A @Rename'd method wins over an unannotated one with the same descriptor, e.g.
            // TObject.equals0(TObject) over the bridge equals(Object) that only calls it.
            if (methods.containsKey(key) && Boolean.TRUE.equals(renamed.get(key)) && r == null) {
                continue;
            }
            methods.put(key, m);
            renamed.put(key, r != null);
        }
        node.methods = new ArrayList<>(methods.values());
    }

    private static boolean has(MethodNode m, String desc) {
        return find(m.invisibleAnnotations, desc) != null || find(m.visibleAnnotations, desc) != null;
    }

    private static AnnotationNode find(List<AnnotationNode> list, String desc) {
        if (list != null) {
            for (AnnotationNode a : list) {
                if (a.desc.equals(desc)) {
                    return a;
                }
            }
        }
        return null;
    }

    static boolean isInterface(ClassNode n) {
        return (n.access & Opcodes.ACC_INTERFACE) != 0;
    }

    List<String> describe() {
        return sourceNames;
    }
}
