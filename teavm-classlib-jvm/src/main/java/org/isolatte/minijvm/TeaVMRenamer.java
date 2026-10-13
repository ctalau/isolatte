package org.isolatte.minijvm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * TeaVM's class library substitution, as TeaVM's compiler applies it ({@code ClasslibSubstitutionPolicy}
 * + {@code ClassRefsRenamer}):
 * <ul>
 * <li>{@code org.teavm.classlib.java.x.TName} becomes {@code java.x.Name} (the {@code T} is dropped
 *     from the top-level simple name only), in every class, so all references agree;</li>
 * <li>{@code @Superclass("")} removes the superclass ({@code TObject} is the root);</li>
 * <li>{@code @Rename("n")} renames a method, replacing a method of the same descriptor;</li>
 * <li>{@code @Remove} drops a method.</li>
 * </ul>
 * One more mapping is specific to miniJVM: TeaVM's class metadata structure {@code ClassInfo} (and
 * its {@code StringInfo}) is retargeted to {@code java.lang.Class} (and {@code String}), and every
 * {@code ClassInfo.m()} call becomes {@code Class.ci$m()}. miniJVM creates the {@code Class} objects
 * itself, so a {@code Class} is its own {@code ClassInfo}; the {@code ci$} methods are natives in
 * {@code jni_teavm.c}.
 */
final class TeaVMRenamer {
    static final String PREFIX = "org/teavm/classlib/";
    static final String CLASS_INFO = "org/teavm/runtime/reflect/ClassInfo";
    static final String STRING_INFO = "org/teavm/runtime/StringInfo";
    private static final String RENAME = "Lorg/teavm/interop/Rename;";
    private static final String SUPERCLASS = "Lorg/teavm/interop/Superclass;";
    private static final String REMOVE = "Lorg/teavm/interop/Remove;";

    static final Remapper REMAPPER = new Remapper() {
        @Override
        public String map(String internalName) {
            return TeaVMRenamer.map(internalName);
        }

        @Override
        public String mapMethodName(String owner, String name, String descriptor) {
            return owner.equals(CLASS_INFO) || owner.equals(STRING_INFO) ? "ci$" + name : name;
        }
    };

    private TeaVMRenamer() {
    }

    static String map(String internalName) {
        if (internalName.equals(CLASS_INFO)) {
            return "java/lang/Class";
        }
        if (internalName.equals(STRING_INFO)) {
            return "java/lang/String";
        }
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

    /** The renamed class, or null for the metadata structures that map onto Class/String. */
    static ClassNode rename(byte[] bytes) {
        ClassReader reader = new ClassReader(bytes);
        if (reader.getClassName().equals(CLASS_INFO) || reader.getClassName().equals(STRING_INFO)) {
            return null;
        }
        ClassNode node = new ClassNode();
        reader.accept(new ClassRemapper(node, REMAPPER), 0);
        applyAnnotations(node);
        return node;
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
        if (node.name.equals(node.superName) || node.name.equals("java/lang/Object")) {
            node.superName = null;
        }
        node.interfaces.removeIf(i -> i.equals(node.name));

        Map<String, MethodNode> methods = new LinkedHashMap<>();
        Map<String, Boolean> renamed = new HashMap<>();
        for (MethodNode m : node.methods) {
            if (find(m.invisibleAnnotations, REMOVE) != null || find(m.visibleAnnotations, REMOVE) != null) {
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
}
