package org.isolatte.guest;

import java.io.IOException;
import java.io.InputStream;
import java.util.AbstractMap;
import java.util.ListResourceBundle;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The bundle table TeaVM's ResourceBundle reads ({@code ResourceBundleImpl.createBundleMap}). TeaVM's
 * compiler builds it from {@code META-INF/services/java.util.ResourceBundle}; here it is lazy: a
 * bundle name maps to a ResourceBundle class of that name or a {@code .properties} resource on the
 * guest class path. Only {@code get} is used by TeaVM's ResourceBundle.
 */
public final class BundleMap extends AbstractMap<String, Supplier<ResourceBundle>> {
    @Override
    public Supplier<ResourceBundle> get(Object key) {
        String name = (String) key;
        try {
            Class<?> cls = Class.forName(name);
            if (ResourceBundle.class.isAssignableFrom(cls)) {
                return () -> {
                    try {
                        return (ResourceBundle) cls.newInstance();
                    } catch (ReflectiveOperationException e) {
                        return null;
                    }
                };
            }
        } catch (ClassNotFoundException e) {
            // try properties
        }
        InputStream in = ClassLoader.getSystemClassLoader().getResourceAsStream(name.replace('.', '/') + ".properties");
        if (in == null) {
            return null;
        }
        Properties props = new Properties();
        try (InputStream input = in) {
            props.load(input);
        } catch (IOException e) {
            return null;
        }
        Object[][] contents = new Object[props.size()][];
        int i = 0;
        for (String k : props.stringPropertyNames()) {
            contents[i++] = new Object[] {k, props.getProperty(k)};
        }
        return () -> new ListResourceBundle() {
            @Override
            protected Object[][] getContents() {
                return contents;
            }
        };
    }

    @Override
    public Set<Map.Entry<String, Supplier<ResourceBundle>>> entrySet() {
        return Set.of();
    }
}
