package org.isolatte.vm;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * The guest's only access to host files: natives of {@code org.isolatte.guest.Jail}, which take
 * virtual paths. A virtual path is normalized lexically ({@code ..} stops at {@code /}), resolved
 * under the jail folder, and canonicalized (symlinks followed); anything whose real path is not
 * inside the folder does not exist. Read-only.
 *
 * <p>The confinement lives in the VM, not in guest code: whatever the guest does, these natives are
 * the whole host file API it has.
 */
final class Jail {
    static final int EXISTS = 1;
    static final int REGULAR = 2;
    static final int DIRECTORY = 4;

    private final Path root;

    Jail(Path folder) throws IOException {
        this.root = folder.toRealPath();
    }

    /** The real host path for a virtual path, or null when it is outside the jail or missing. */
    Path resolve(String virtual) {
        if (virtual == null) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        for (String p : virtual.split("/")) {
            if (p.isEmpty() || p.equals(".")) {
                continue;
            }
            if (p.equals("..")) {
                if (!parts.isEmpty()) {
                    parts.remove(parts.size() - 1);
                }
            } else {
                parts.add(p);
            }
        }
        try {
            Path p = root;
            for (String part : parts) {
                p = p.resolve(part);
            }
            Path real = p.toRealPath();
            return real.startsWith(root) ? real : null;
        } catch (IOException | java.nio.file.InvalidPathException e) {
            return null; // e.g. a NUL in the name
        }
    }

    void register(VM vm) {
        String j = "org/isolatte/guest/Jail.";
        vm.natives.put(j + "attributes(Ljava/lang/String;)I", a -> {
            Path p = resolve(VM.host(a[0]));
            if (p == null) {
                return 0;
            }
            return EXISTS | (Files.isRegularFile(p) ? REGULAR : 0) | (Files.isDirectory(p) ? DIRECTORY : 0);
        });
        vm.natives.put(j + "list(Ljava/lang/String;)[Ljava/lang/String;", a -> {
            Path p = resolve(VM.host(a[0]));
            if (p == null || !Files.isDirectory(p)) {
                return null;
            }
            try (Stream<Path> s = Files.list(p)) {
                Object[] names = s.map(x -> vm.str(x.getFileName().toString())).toArray();
                return new RefArray(vm.arrayOf(vm.stringClass), names);
            } catch (IOException e) {
                return null;
            }
        });
        vm.natives.put(j + "length(Ljava/lang/String;)J", a -> {
            Path p = resolve(VM.host(a[0]));
            try {
                return p == null ? 0L : Files.size(p);
            } catch (IOException e) {
                return 0L;
            }
        });
        vm.natives.put(j + "lastModified(Ljava/lang/String;)J", a -> {
            Path p = resolve(VM.host(a[0]));
            try {
                return p == null ? 0L : Files.getLastModifiedTime(p, LinkOption.NOFOLLOW_LINKS).toMillis();
            } catch (IOException e) {
                return 0L;
            }
        });
        vm.natives.put(j + "read(Ljava/lang/String;)[B", a -> {
            Path p = resolve(VM.host(a[0]));
            try {
                return p == null || !Files.isRegularFile(p) ? null : Files.readAllBytes(p);
            } catch (IOException e) {
                return null;
            }
        });
    }
}
