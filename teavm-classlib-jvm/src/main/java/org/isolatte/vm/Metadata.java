package org.isolatte.vm;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.teavm.classlib.impl.unicode.CLDRReader;
import org.teavm.model.ClassReaderSource;
import org.teavm.model.MethodReference;
import org.teavm.parsing.resource.ResourceProvider;
import org.teavm.platform.metadata.MetadataGenerator;
import org.teavm.platform.metadata.MetadataGeneratorContext;
import org.teavm.platform.metadata.builders.IntResourceBuilder;
import org.teavm.platform.metadata.builders.ObjectResourceBuilder;
import org.teavm.platform.metadata.builders.ResourceArrayBuilder;
import org.teavm.platform.metadata.builders.ResourceBuilder;
import org.teavm.platform.metadata.builders.ResourceMapBuilder;
import org.teavm.platform.metadata.builders.StringResourceBuilder;
import org.teavm.platform.plugin.MetadataRegistration;

/**
 * TeaVM's class library gets its Unicode and CLDR tables from metadata natives: TeaVM's compiler
 * runs a host-side {@link MetadataGenerator} per native and embeds the result. This VM does the same
 * lazily, on first call: it takes the registrations from TeaVM's own {@code JCLPlugin}, runs the
 * generator on the host, and gives the guest {@code Resource} objects built from the result.
 */
final class Metadata {
    private final VM vm;
    private final ResourceProvider resources;
    private final Map<String, VClass> resourceClasses = new HashMap<>();

    private Metadata(VM vm, List<File> classlib) {
        this.vm = vm;
        this.resources = ResourceProvider.ofClassPath(classlib);
    }

    static void register(VM vm, List<File> classlib) throws ReflectiveOperationException {
        Metadata md = new Metadata(vm, classlib);
        Class<?> plugin = Class.forName("org.teavm.classlib.impl.JCLPlugin");
        Method install = plugin.getDeclaredMethod("installMetadata", MetadataRegistration.class);
        install.setAccessible(true);
        install.invoke(plugin.getDeclaredConstructor().newInstance(), (MetadataRegistration) md::add);
    }

    private void add(MethodReference method, MetadataGenerator generator) {
        String key = method.getClassName().replace('.', '/') + "." + method.getName()
                + Loader.map(method.getDescriptor().toString().substring(method.getName().length()));
        Object[] cache = new Object[1];
        vm.natives.put(key, a -> {
            if (cache[0] == null) {
                ResourceBuilder b = generator.generateMetadata(context(), method);
                cache[0] = toGuest(b);
            }
            return cache[0];
        });
    }

    private MetadataGeneratorContext context() {
        return new MetadataGeneratorContext() {
            @Override
            public ClassReaderSource getClassSource() {
                return null;
            }

            @Override
            public ClassLoader getClassLoader() {
                return Metadata.class.getClassLoader();
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
                if (type == CLDRReader.class) {
                    return type.cast(CLDRReader.getInstance(getProperties(), resources));
                }
                return null;
            }
        };
    }

    private VClass resourceClass(String iface, Map<String, Native> impls) {
        return resourceClasses.computeIfAbsent(iface + "#" + impls.keySet(),
                k -> vm.synthetic(iface + "$$Metadata$" + resourceClasses.size(), List.of(vm.load(iface)), impls, null));
    }

    private VObject instance(VClass c, Object state) {
        VObject o = new VObject(c);
        o.hidden = state;
        return o;
    }

    private Object toGuest(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof StringResourceBuilder s) {
            Map<String, Native> m = new LinkedHashMap<>();
            m.put("getValue()Ljava/lang/String;", a -> vm.str((String) ((VObject) a[0]).hidden));
            return instance(resourceClass("org/teavm/platform/metadata/StringResource", m), s.value);
        }
        if (value instanceof IntResourceBuilder s) {
            Map<String, Native> m = new LinkedHashMap<>();
            m.put("getValue()I", a -> ((VObject) a[0]).hidden);
            return instance(resourceClass("org/teavm/platform/metadata/IntResource", m), s.value);
        }
        if (value instanceof ResourceMapBuilder<?> s) {
            Map<String, Object> guest = new LinkedHashMap<>();
            for (var e : s.values.entrySet()) {
                guest.put(e.getKey(), toGuest(e.getValue()));
            }
            Map<String, Native> m = new LinkedHashMap<>();
            m.put("has(Ljava/lang/String;)Z", a -> map(a).containsKey(VM.host(a[1])) ? 1 : 0);
            m.put("get(Ljava/lang/String;)Lorg/teavm/platform/metadata/Resource;", a -> map(a).get(VM.host(a[1])));
            m.put("keys()[Ljava/lang/String;", a -> new RefArray(vm.arrayOf(vm.stringClass),
                    map(a).keySet().stream().map(vm::str).toArray()));
            return instance(resourceClass("org/teavm/platform/metadata/ResourceMap", m), guest);
        }
        if (value instanceof ResourceArrayBuilder<?> s) {
            List<Object> guest = new ArrayList<>();
            for (var e : s.values) {
                guest.add(toGuest(e));
            }
            Map<String, Native> m = new LinkedHashMap<>();
            m.put("size()I", a -> list(a).size());
            m.put("get(I)Lorg/teavm/platform/metadata/Resource;", a -> list(a).get((Integer) a[1]));
            m.put("add(Lorg/teavm/platform/metadata/Resource;)V", a -> {
                list(a).add(a[1]);
                return null;
            });
            return instance(resourceClass("org/teavm/platform/metadata/ResourceArray", m), guest);
        }
        if (value instanceof ObjectResourceBuilder s) {
            String[] names = s.fieldNames();
            Map<String, Object> fields = new HashMap<>();
            for (int i = 0; i < names.length; i++) {
                fields.put(names[i], toGuest(s.getValue(i)));
            }
            String iface = s.getOutputClass().getName().replace('.', '/');
            Map<String, Native> m = new LinkedHashMap<>();
            for (Method getter : s.getOutputClass().getMethods()) {
                String n = getter.getName();
                String field = n.startsWith("get") ? n.substring(3) : n.startsWith("is") ? n.substring(2) : null;
                if (field == null || getter.getParameterCount() != 0 || field.isEmpty()) {
                    continue;
                }
                String prop = Character.toLowerCase(field.charAt(0)) + field.substring(1);
                String desc = Loader.map(org.objectweb.asm.Type.getMethodDescriptor(getter));
                m.put(n + desc, a -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> f = (Map<String, Object>) ((VObject) a[0]).hidden;
                    return f.get(prop);
                });
            }
            return instance(resourceClass(iface, m), fields);
        }
        if (value instanceof String str) {
            return vm.str(str);
        }
        if (value instanceof Boolean b) {
            return b ? 1 : 0;
        }
        if (value instanceof Character c) {
            return (int) c;
        }
        if (value instanceof Byte || value instanceof Short) {
            return ((Number) value).intValue();
        }
        if (value instanceof Number) {
            return value;
        }
        throw new IllegalStateException("unsupported metadata value " + value.getClass());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object[] a) {
        return (Map<String, Object>) ((VObject) a[0]).hidden;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object[] a) {
        return (List<Object>) ((VObject) a[0]).hidden;
    }
}
