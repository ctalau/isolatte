import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jgit.http.server.GitServlet;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

import java.io.File;

/**
 * Minimal JGit HTTP server to reproduce the Protocol V2 path traversal
 * vulnerability.
 *
 * Compile:
 *   CP=$(find lib/ -name "*.jar" | tr '\n' ':')
 *   javac -cp "$CP" JGitServer.java -d .
 *
 * Run:
 *   java -cp ".:$CP" JGitServer /path/to/repo.git 7070
 *
 * To enable the want-ref attack surface also set in the repo config:
 *   [uploadpack]
 *       allowRefInWant = true
 *
 * JGit version tested: 7.5.0.202512021534-r
 * Jetty version:       12.0.16 (EE10 / Jakarta Servlet API)
 */
public class JGitServer {
    public static void main(String[] args) throws Exception {
        String repoPath = args.length > 0 ? args[0] : "/tmp/jgit-vuln-demo/served.git";
        int port       = args.length > 1 ? Integer.parseInt(args[1]) : 7070;

        Repository repo = new FileRepositoryBuilder()
                .setGitDir(new File(repoPath))
                .build();

        GitServlet gs = new GitServlet();
        gs.setRepositoryResolver((req, name) -> {
            repo.incrementOpen();
            return repo;
        });
        // No auth filter, no RefFilter — default (vulnerable) code path.
        // UploadPack.exactRefs() fast-path passes client-supplied want-ref
        // strings directly to RefDatabase.exactRef() without validation.

        Server server = new Server(port);
        ServletContextHandler ctx = new ServletContextHandler();
        ctx.setContextPath("/");
        ctx.addServlet(new ServletHolder(gs), "/*");
        server.setHandler(ctx);

        server.start();
        System.out.println("[*] JGit HTTP server on http://localhost:" + port + "/repo.git");
        System.out.println("[*] Repository: " + repoPath);
        server.join();
    }
}
