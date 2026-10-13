package org.isolatte.overlay;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Writes each base-locale {@code .properties} resource bundle of a jar as ListResourceBundle source.
 *
 * <p>Under the folder jail, OpenJDK finds boot-class-path resources with Java code (URLClassPath over
 * java.io.File), which only sees the jail, whereas HotSpot loads boot-class-path classes natively.
 * ResourceBundle tries a class named after the bundle before the properties file, so compiled bundles
 * keep Xerces' diagnostics working without exposing the jar through java.io.
 *
 * <p>Usage: {@code BundleCompiler <jar> <package/prefix/> <outSourceDir>}
 */
public final class BundleCompiler {
    public static void main(String[] args) throws IOException {
        Path out = Path.of(args[2]);
        try (JarFile jar = new JarFile(args[0])) {
            for (JarEntry e : jar.stream().toList()) {
                String name = e.getName();
                String simple = name.substring(name.lastIndexOf('/') + 1);
                if (!name.startsWith(args[1]) || !simple.endsWith(".properties") || simple.contains("_")) {
                    continue;
                }
                Properties props = new Properties();
                try (InputStream in = jar.getInputStream(e)) {
                    props.load(in);
                }
                String internal = name.substring(0, name.length() - ".properties".length());
                String pkg = internal.substring(0, internal.lastIndexOf('/')).replace('/', '.');
                String cls = internal.substring(internal.lastIndexOf('/') + 1);
                StringBuilder src = new StringBuilder();
                src.append("package ").append(pkg).append(";\n\n")
                        .append("/** Generated from ").append(name).append(" by BundleCompiler. */\n")
                        .append("public final class ").append(cls).append(" extends java.util.ListResourceBundle {\n")
                        .append("    @Override\n    protected Object[][] getContents() {\n")
                        .append("        return new Object[][] {\n");
                for (String key : new TreeSet<>(props.stringPropertyNames())) {
                    src.append("            {").append(literal(key)).append(", ")
                            .append(literal(props.getProperty(key))).append("},\n");
                }
                src.append("        };\n    }\n}\n");
                Path file = out.resolve(internal + ".java");
                Files.createDirectories(file.getParent());
                Files.writeString(file, src, StandardCharsets.UTF_8);
            }
        }
    }

    private static String literal(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }

    private BundleCompiler() {
    }
}
