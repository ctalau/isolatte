package org.isolatte.minijvm;

import static org.objectweb.asm.Opcodes.*;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.objectweb.asm.Label;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.teavm.classlib.impl.unicode.CLDRReader;
import org.teavm.model.ClassReaderSource;
import org.teavm.model.MethodReference;
import org.teavm.parsing.resource.ResourceProvider;
import org.teavm.platform.metadata.MetadataGenerator;
import org.teavm.platform.metadata.MetadataGeneratorContext;
import org.teavm.platform.metadata.builders.IntResourceBuilder;
import org.teavm.platform.metadata.builders.ObjectResourceBuilder;
import org.teavm.platform.metadata.builders.ResourceArrayBuilder;
import org.teavm.platform.metadata.builders.ResourceMapBuilder;
import org.teavm.platform.metadata.builders.StringResourceBuilder;
import org.teavm.platform.plugin.MetadataRegistration;

/**
 * TeaVM's class library gets its Unicode and CLDR tables from metadata natives that TeaVM's compiler
 * fills in at build time by running host-side generators. This does the same for miniJVM: it takes
 * the registrations from TeaVM's own {@code JCLPlugin.installMetadata}, runs the generator of each
 * native that ends up in the runtime, and replaces the native with a method that decodes the
 * serialized result ({@code org.isolatte.guest.Res}).
 */
final class MetadataBaker {
    static final String FACTORY = "org/isolatte/guest/ResFactory";
    private static final int CHUNK = 20000;

    private final Map<String, MethodReference> methods = new HashMap<>();
    private final Map<String, MetadataGenerator> generators = new HashMap<>();
    private final ResourceProvider resources;
    private final Map<Class<?>, Integer> objectTypes = new LinkedHashMap<>();
    final List<String> baked = new ArrayList<>();

    MetadataBaker(List<File> classlib) throws ReflectiveOperationException {
        resources = ResourceProvider.ofClassPath(classlib);
        Class<?> plugin = Class.forName("org.teavm.classlib.impl.JCLPlugin");
        Method install = plugin.getDeclaredMethod("installMetadata", MetadataRegistration.class);
        install.setAccessible(true);
        install.invoke(plugin.getDeclaredConstructor().newInstance(), (MetadataRegistration) (method, generator) -> {
            String key = key(method.getClassName().replace('.', '/'), method.getName(),
                    TeaVMRenamer.map(method.getDescriptor().toString().substring(method.getName().length())));
            methods.put(key, method);
            generators.put(key, generator);
        });
    }

    private static String key(String owner, String name, String desc) {
        return owner + "." + name + desc;
    }

    /** Replaces the metadata natives of {@code cls}, if any. */
    void bake(ClassNode cls) {
        for (int i = 0; i < cls.methods.size(); i++) {
            MethodNode m = cls.methods.get(i);
            String key = key(cls.name, m.name, mapDesc(m.desc));
            MetadataGenerator g = generators.get(key);
            if (g == null || (m.access & ACC_NATIVE) == 0) {
                continue;
            }
            Object value = g.generateMetadata(context(), methods.get(key));
            StringBuilder sb = new StringBuilder();
            encode(value, sb);
            m.access &= ~ACC_NATIVE;
            m.instructions = new InsnList();
            m.tryCatchBlocks = new ArrayList<>();
            InsnList c = m.instructions;
            String data = sb.toString();
            c.add(new TypeInsnNode(NEW, "java/lang/StringBuilder"));
            c.add(new InsnNode(DUP));
            c.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
            for (int off = 0; off < data.length(); off += CHUNK) {
                c.add(new LdcInsnNode(data.substring(off, Math.min(data.length(), off + CHUNK))));
                c.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                        "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
            }
            c.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false));
            c.add(new TypeInsnNode(NEW, FACTORY));
            c.add(new InsnNode(DUP));
            c.add(new MethodInsnNode(INVOKESPECIAL, FACTORY, "<init>", "()V", false));
            c.add(new MethodInsnNode(INVOKESTATIC, "org/isolatte/guest/Res", "decode",
                    "(Ljava/lang/String;Lorg/isolatte/guest/Res$Factory;)Ljava/lang/Object;", false));
            c.add(new TypeInsnNode(CHECKCAST, Type.getReturnType(m.desc).getInternalName()));
            c.add(new InsnNode(ARETURN));
            baked.add(key + " (" + data.length() + " chars)");
        }
    }

    private static String mapDesc(String desc) {
        return desc; // already renamed
    }

    private MetadataGeneratorContext context() {
        return new MetadataGeneratorContext() {
            @Override
            public ClassReaderSource getClassSource() {
                return null;
            }

            @Override
            public ClassLoader getClassLoader() {
                return MetadataBaker.class.getClassLoader();
            }

            @Override
            public ResourceProvider getResourceProvider() {
                return resources;
            }

            @Override
            public Properties getProperties() {
                return new Properties();
            }

            @Override
            public <T> T getService(Class<T> type) {
                return type == CLDRReader.class ? type.cast(CLDRReader.getInstance(getProperties(), resources)) : null;
            }
        };
    }

    private static void string(String s, StringBuilder sb) {
        sb.append(s.length()).append(':').append(s);
    }

    private void encode(Object v, StringBuilder sb) {
        if (v == null) {
            sb.append('N');
        } else if (v instanceof StringResourceBuilder s) {
            if (s.value == null) {
                sb.append('N');
            } else {
                sb.append('S');
                string(s.value, sb);
            }
        } else if (v instanceof IntResourceBuilder s) {
            sb.append('I').append(s.value).append(';');
        } else if (v instanceof ResourceMapBuilder<?> s) {
            sb.append('M').append(s.values.size()).append(';');
            for (var e : s.values.entrySet()) {
                string(e.getKey(), sb);
                encode(e.getValue(), sb);
            }
        } else if (v instanceof ResourceArrayBuilder<?> s) {
            sb.append('A').append(s.values.size()).append(';');
            for (var e : s.values) {
                encode(e, sb);
            }
        } else if (v instanceof ObjectResourceBuilder s) {
            int type = objectTypes.computeIfAbsent(s.getOutputClass(), k -> objectTypes.size());
            String[] names = s.fieldNames();
            sb.append('O').append(type).append(';').append(names.length).append(';');
            for (int i = 0; i < names.length; i++) {
                string(names[i], sb);
                encode(s.getValue(i), sb);
            }
        } else if (v instanceof String s) {
            sb.append('s');
            string(s, sb);
        } else if (v instanceof Integer i) {
            sb.append('i').append(i).append(';');
        } else if (v instanceof Boolean b) {
            sb.append('z').append(b ? 1 : 0).append(';');
        } else if (v instanceof Character ch) {
            sb.append('c').append((int) ch).append(';');
        } else if (v instanceof Byte b) {
            sb.append('b').append(b).append(';');
        } else if (v instanceof Short sh) {
            sb.append('h').append(sh).append(';');
        } else if (v instanceof Long l) {
            sb.append('l').append(l).append(';');
        } else if (v instanceof Float f) {
            sb.append('f').append(Float.floatToRawIntBits(f)).append(';');
        } else if (v instanceof Double d) {
            sb.append('d').append(Double.doubleToRawLongBits(d)).append(';');
        } else {
            throw new IllegalStateException("unsupported metadata value " + v.getClass());
        }
    }

    /** The factory and one class per object resource interface used by the baked methods. */
    List<ClassNode> generatedClasses() {
        List<ClassNode> out = new ArrayList<>();
        ClassNode f = new ClassNode();
        f.version = V1_6;
        f.access = ACC_PUBLIC | ACC_FINAL | ACC_SUPER;
        f.name = FACTORY;
        f.superName = "java/lang/Object";
        f.interfaces.add("org/isolatte/guest/Res$Factory");
        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "()V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        init.instructions.add(new InsnNode(RETURN));
        f.methods.add(init);
        MethodNode create = new MethodNode(ACC_PUBLIC, "create", "(ILjava/util/Map;)Ljava/lang/Object;", null, null);
        LabelNode dflt = new LabelNode(new Label());
        LabelNode[] labels = new LabelNode[Math.max(1, objectTypes.size())];
        for (int i = 0; i < labels.length; i++) {
            labels[i] = new LabelNode(new Label());
        }
        create.instructions.add(new VarInsnNode(ILOAD, 1));
        create.instructions.add(new TableSwitchInsnNode(0, labels.length - 1, dflt, labels));
        for (var e : objectTypes.entrySet()) {
            String impl = "org/isolatte/guest/ResImpl$" + e.getValue();
            create.instructions.add(labels[e.getValue()]);
            create.instructions.add(new TypeInsnNode(NEW, impl));
            create.instructions.add(new InsnNode(DUP));
            create.instructions.add(new VarInsnNode(ALOAD, 2));
            create.instructions.add(new MethodInsnNode(INVOKESPECIAL, impl, "<init>", "(Ljava/util/Map;)V", false));
            create.instructions.add(new InsnNode(ARETURN));
            out.add(impl(impl, e.getKey()));
        }
        if (objectTypes.isEmpty()) {
            create.instructions.add(labels[0]);
        }
        create.instructions.add(dflt);
        create.instructions.add(new InsnNode(ACONST_NULL));
        create.instructions.add(new InsnNode(ARETURN));
        f.methods.add(create);
        out.add(f);
        return out;
    }

    private static ClassNode impl(String name, Class<?> iface) {
        ClassNode c = new ClassNode();
        c.version = V1_6;
        c.access = ACC_PUBLIC | ACC_FINAL | ACC_SUPER;
        c.name = name;
        c.superName = "org/isolatte/guest/ObjRes";
        c.interfaces.add(TeaVMRenamer.map(Type.getInternalName(iface)));
        MethodNode init = new MethodNode(ACC_PUBLIC, "<init>", "(Ljava/util/Map;)V", null, null);
        init.instructions.add(new VarInsnNode(ALOAD, 0));
        init.instructions.add(new VarInsnNode(ALOAD, 1));
        init.instructions.add(new MethodInsnNode(INVOKESPECIAL, c.superName, "<init>", "(Ljava/util/Map;)V", false));
        init.instructions.add(new InsnNode(RETURN));
        c.methods.add(init);
        for (Method getter : iface.getMethods()) {
            String n = getter.getName();
            String field = n.startsWith("get") ? n.substring(3) : n.startsWith("is") ? n.substring(2) : null;
            if (field == null || field.isEmpty() || getter.getParameterCount() != 0 || getter.isDefault()) {
                continue;
            }
            String prop = Character.toLowerCase(field.charAt(0)) + field.substring(1);
            Type ret = Type.getType(TeaVMRenamer.REMAPPER.mapDesc(Type.getDescriptor(getter.getReturnType())));
            MethodNode m = new MethodNode(ACC_PUBLIC, n, "()" + ret.getDescriptor(), null, null);
            m.instructions.add(new VarInsnNode(ALOAD, 0));
            m.instructions.add(new LdcInsnNode(prop));
            m.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, c.superName, "get", "(Ljava/lang/String;)Ljava/lang/Object;", false));
            if (ret.getSort() < Type.ARRAY) {
                String box = IndyDesugar.boxOf(ret);
                m.instructions.add(new TypeInsnNode(CHECKCAST, box));
                m.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, box, ret.getClassName() + "Value", "()" + ret.getDescriptor(), false));
            } else if (!ret.getDescriptor().equals("Ljava/lang/Object;")) {
                m.instructions.add(new TypeInsnNode(CHECKCAST, ret.getSort() == Type.ARRAY ? ret.getDescriptor() : ret.getInternalName()));
            }
            m.instructions.add(new InsnNode(ret.getOpcode(IRETURN)));
            c.methods.add(m);
        }
        return c;
    }
}
