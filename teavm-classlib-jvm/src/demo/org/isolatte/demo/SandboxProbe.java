package org.isolatte.demo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Tries the usual ways out of a Java program and prints what each one did. Plain application code;
 * run it on stock HotSpot and on miniJVM with TeaVM's class library to compare.
 */
public final class SandboxProbe {
    public static void main(String[] args) {
        check("java.io read /etc/passwd", () -> {
            try (FileInputStream in = new FileInputStream("/etc/passwd")) {
                return in.readAllBytes().length + " bytes";
            }
        });
        check("java.io write /tmp/isolatte-probe", () -> {
            File f = new File("/tmp/isolatte-probe");
            try (FileOutputStream out = new FileOutputStream(f)) {
                out.write('x');
            }
            return "wrote, deleted: " + f.delete();
        });
        check("NIO read /etc/passwd", () -> Files.readAllBytes(Path.of("/etc/passwd")).length + " bytes");
        check("NIO list /", () -> {
            try (var s = Files.list(Path.of("/"))) {
                return s.count() + " entries";
            }
        });
        check("ProcessBuilder(\"true\")", () -> "exit " + new ProcessBuilder("true").start().waitFor());
        check("Runtime.exec(\"true\")", () -> "exit " + Runtime.getRuntime().exec(new String[] {"true"}).waitFor());
        check("Socket connect 127.0.0.1:9", () -> {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", 9), 500);
                return "connected";
            }
        });
        check("URL http://127.0.0.1:9/", () -> new URL("http://127.0.0.1:9/").openStream().read());
        check("System.loadLibrary(\"z\")", () -> {
            System.loadLibrary("z");
            return "loaded";
        });
        check("System.getenv(\"PATH\")", () -> System.getenv("PATH"));
        check("System.getProperty(\"user.home\")", () -> System.getProperty("user.home"));
        check("class path resource ../../etc/passwd", () -> {
            var in = SandboxProbe.class.getClassLoader().getResourceAsStream("../../../../../../../../etc/passwd");
            return in == null ? null : in.readAllBytes().length + " bytes";
        });
        check("miniJVM file native via own class", () -> {
            long handle = org.mini.fs.InnerFile.openFile("/etc/passwd\0".getBytes(), "rb\0".getBytes());
            return handle != 0 ? "opened host /etc/passwd" : "no handle";
        });
        check("Class.forName(\"sun.misc.Unsafe\")", () -> Class.forName("sun.misc.Unsafe"));
    }

    private static void check(String what, Callable<Object> action) {
        String result;
        try {
            result = "ALLOWED  " + action.call();
        } catch (Throwable t) {
            result = "blocked  " + t.getClass().getName() + (t.getMessage() != null ? ": " + t.getMessage() : "");
        }
        System.out.println(String.format("%-36s %s", what, result));
    }

    private SandboxProbe() {
    }
}
