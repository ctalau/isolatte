import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Negative tests executed as Java bytecode in the guest JVM. */
public final class ProbeSandbox {
    private static boolean canRead(String path) {
        try (FileInputStream stream = new FileInputStream(path)) { return stream.read() >= 0; }
        catch (Throwable error) { return false; }
    }
    private static boolean writeDenied(String path) {
        try (FileOutputStream stream = new FileOutputStream(path, true)) {
            stream.write(88);
            return false;
        } catch (Throwable error) { return true; }
    }
    public static String probe() {
        boolean nioDenied;
        try { Files.write(Paths.get("/tmp/nio.txt"), new byte[] {88}); nioDenied = false; }
        catch (Throwable error) { nioDenied = true; }
        boolean subprocessDenied;
        try { new ProcessBuilder("sh", "-c", "true").start(); subprocessDenied = false; }
        catch (Throwable error) { subprocessDenied = true; }
        boolean nativeLibraryDenied;
        try { System.load("/app/nonexistent.so"); nativeLibraryDenied = false; }
        catch (Throwable error) { nativeLibraryDenied = true; }
        return "{\"inputReadable\":" + canRead("/input/sample.xml")
            + ",\"hostPasswdHidden\":" + !canRead("/etc/passwd")
            + ",\"runtimeFilesVisibleToJava\":" + canRead("/jdk/release")
            + ",\"runtimeWriteDenied\":" + writeDenied("/jdk/release")
            + ",\"inputWriteDenied\":" + writeDenied("/input/sample.xml")
            + ",\"scratchWriteDenied\":" + writeDenied("/tmp/probe.txt")
            + ",\"nioWriteDenied\":" + nioDenied
            + ",\"hostEnvironmentHidden\":" + (System.getenv("HOME") == null)
            + ",\"subprocessDenied\":" + subprocessDenied
            + ",\"nativeLibraryDenied\":" + nativeLibraryDenied + "}";
    }
}
