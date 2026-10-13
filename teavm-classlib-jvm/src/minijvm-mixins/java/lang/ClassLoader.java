package java.lang;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import jdk.internal.mixin.MixinReplace;

/**
 * Mixin: TeaVM's ClassLoader has no loadClass (its world is closed at compile time) and serves the
 * resources embedded at compile time from a JavaScript object. Here both come from the boot class
 * path jar, read-only.
 */
public abstract class ClassLoader {
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        return Class.forName(name, false, null);
    }

    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        return Class.forName(name, false, null);
    }

    @MixinReplace
    public InputStream getResourceAsStream(String name) {
        if (name == null) {
            return null;
        }
        byte[] bytes = org.isolatte.guest.Resources.read(name.startsWith("/") ? name.substring(1) : name);
        return bytes == null ? null : new ByteArrayInputStream(bytes);
    }
}
