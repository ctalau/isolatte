package org.isolatte.overlay;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Merges compatibility mixins into the renamed TeaVM classes.
 *
 * <p>A mixin is a Java source file with the same name as an overlay class (e.g. {@code java.io.File}),
 * compiled with {@code --patch-module java.base=<overlay>}. Its members are added to the TeaVM class,
 * except members annotated {@code @MixinProvided}: those only exist so the mixin compiles and TeaVM
 * supplies them. A member annotated {@code @MixinReplace} replaces TeaVM's member of the same
 * signature. A mixin static initializer runs before TeaVM's. A compiled class that does not match an
 * overlay class is copied as a new helper class.
 *
 * <p>Usage: {@code MixinMerger <overlayDir> <compiledMixinDir>}; the overlay is updated in place.
 */
public final class MixinMerger {
    private static final String PROVIDED = "Ljdk/internal/io/MixinProvided;";
    private static final String REPLACE = "Ljdk/internal/io/MixinReplace;";

    public static void main(String[] args) throws IOException {
        Path overlay = Path.of(args[0]);
        Path mixins = Path.of(args[1]);
        List<Path> files;
        try (Stream<Path> s = Files.walk(mixins)) {
            files = s.filter(p -> p.toString().endsWith(".class")).sorted().toList();
        }
        for (Path mixinFile : files) {
            String internal = mixins.relativize(mixinFile).toString().replace('\\', '/');
            internal = internal.substring(0, internal.length() - 6);
            Path target = overlay.resolve(internal + ".class");
            if (internal.equals("jdk/internal/io/MixinProvided") || internal.equals("jdk/internal/io/MixinReplace")) {
                continue;
            }
            if (!Files.exists(target)) {
                Files.createDirectories(target.getParent());
                Files.copy(mixinFile, target);
                System.out.println("helper  " + internal);
                continue;
            }
            ClassNode base = read(target);
            ClassNode mixin = read(mixinFile);
            merge(base, mixin);
            ClassWriter writer = new ClassWriter(0);
            base.accept(writer);
            Files.write(target, writer.toByteArray());
        }
    }

    private static void merge(ClassNode base, ClassNode mixin) {
        if (!base.superName.equals(mixin.superName)) {
            throw new IllegalStateException(base.name + ": mixin extends " + mixin.superName
                    + ", TeaVM class extends " + base.superName);
        }
        for (String itf : mixin.interfaces) {
            if (!base.interfaces.contains(itf)) {
                base.interfaces.add(itf);
            }
        }
        List<String> log = new ArrayList<>();
        for (FieldNode f : mixin.fields) {
            if (has(f.invisibleAnnotations, PROVIDED)) {
                continue;
            }
            for (FieldNode existing : base.fields) {
                if (existing.name.equals(f.name)) {
                    throw new IllegalStateException(base.name + "." + f.name + " already exists in TeaVM");
                }
            }
            base.fields.add(f);
            log.add("+field " + f.name);
        }
        for (MethodNode m : mixin.methods) {
            if (has(m.invisibleAnnotations, PROVIDED)) {
                continue;
            }
            MethodNode existing = find(base, m.name, m.desc);
            if (m.name.equals("<clinit>")) {
                if (existing == null) {
                    base.methods.add(m);
                } else {
                    // Run the mixin's static initializer first (e.g. JNI initIDs), then TeaVM's.
                    m.name = "mixin$clinit";
                    m.access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
                    base.methods.add(m);
                    InsnList call = new InsnList();
                    call.add(new MethodInsnNode(Opcodes.INVOKESTATIC, base.name, m.name, "()V", false));
                    existing.instructions.insert(call);
                }
                log.add("+<clinit>");
            } else if (has(m.invisibleAnnotations, REPLACE)) {
                if (existing == null) {
                    throw new IllegalStateException(base.name + "." + m.name + m.desc + ": nothing to replace");
                }
                base.methods.set(base.methods.indexOf(existing), m);
                log.add("~" + m.name + m.desc);
            } else {
                if (existing != null) {
                    throw new IllegalStateException(base.name + "." + m.name + m.desc
                            + " already exists in TeaVM; annotate it @MixinProvided or @MixinReplace");
                }
                base.methods.add(m);
                log.add("+" + m.name + m.desc);
            }
        }
        System.out.println("mixin   " + base.name + ": " + String.join(", ", log));
    }

    private static MethodNode find(ClassNode cls, String name, String desc) {
        for (MethodNode m : cls.methods) {
            if (m.name.equals(name) && m.desc.equals(desc)) {
                return m;
            }
        }
        return null;
    }

    private static boolean has(List<AnnotationNode> annotations, String desc) {
        if (annotations != null) {
            for (AnnotationNode a : annotations) {
                if (a.desc.equals(desc)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static ClassNode read(Path file) throws IOException {
        ClassNode node = new ClassNode();
        new ClassReader(Files.readAllBytes(file)).accept(node, 0);
        return node;
    }

    private MixinMerger() {
    }
}
