// DTD validation of DITA topics with validators compiled from the DTDs.
//
// GeneratedDtd.java (made by compiled/gen.py) holds every content model as a
// minimized DFA plus the attribute declarations and entities, as packed char
// tables; nothing DTD-related is parsed at run time. The JDK's built-in SAX
// parser supplies the XML events, with external DTD loading turned off.
//
// usage: java CompiledValidator THREADS [PASSES] < file-list
//   VERBOSE=1 prints errors; PARSE_ONLY=1 runs the SAX parser without validating.
// Each pass re-validates the whole list in the same JVM and prints one line:
// pass 1 is a cold JVM, later passes are JIT-warmed.

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.Pattern;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.*;
import org.xml.sax.ext.DeclHandler;
import org.xml.sax.ext.LexicalHandler;
import org.xml.sax.helpers.DefaultHandler;

public class CompiledValidator extends DefaultHandler implements LexicalHandler, DeclHandler {
    static final int EMPTY = 1, ANY = 2, MIXED = 3, ELEMENT = 4;
    /** Content state after an error, so one bad child is reported once. */
    static final int DEAD = -1;
    static final int T_CDATA = 0, T_ID = 1, T_IDREF = 2, T_IDREFS = 3, T_NMTOKEN = 6, T_NMTOKENS = 7;
    static final int D_REQUIRED = 1, D_FIXED = 2;

    static final String NAME_START = ":A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D"
        + "\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF"
        + "\\uFDF0-\\uFFFD\\x{10000}-\\x{EFFFF}";
    static final String NAME_CHAR = NAME_START + "\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040";
    static final Pattern IS_NAME = Pattern.compile("[" + NAME_START + "][" + NAME_CHAR + "]*");
    static final Pattern IS_NMTOKEN = Pattern.compile("[" + NAME_CHAR + "]+");

    static final Map<String, GeneratedDtd.Shell> SHELL_BY_PUBLIC = new HashMap<>();
    static {
        for (GeneratedDtd.Shell s : GeneratedDtd.SHELLS) SHELL_BY_PUBLIC.put(s.publicId, s);
    }

    // Per-document state.
    GeneratedDtd.Shell shell;
    String doctypeName = "";
    boolean seenRoot, stop, inCdata, inDtd;
    int depth;
    int[] kinds = new int[64], states = new int[64];
    final Set<String> ids = new HashSet<>();
    final List<String> idrefs = new ArrayList<>();
    int errors;
    List<String> messages;

    void reset(boolean verbose) {
        shell = null;
        doctypeName = "";
        seenRoot = stop = inCdata = inDtd = false;
        depth = 0;
        ids.clear();
        idrefs.clear();
        errors = 0;
        messages = verbose ? new ArrayList<>() : null;
    }

    void error(String msg) {
        errors++;
        if (messages != null) messages.add(msg);
    }

    static int step(int state, int sym) {
        int lo = GeneratedDtd.TRANS_OFF[state], hi = GeneratedDtd.TRANS_OFF[state + 1] - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1, s = GeneratedDtd.TRANS_SYM[mid];
            if (s == sym) return GeneratedDtd.TRANS_NEXT[mid];
            if (s < sym) lo = mid + 1; else hi = mid - 1;
        }
        return -1;
    }

    /** Non-CDATA attribute normalization: trim and collapse runs of spaces. */
    static String collapse(String v) {
        if (v.indexOf("  ") < 0 && !v.startsWith(" ") && !v.endsWith(" ")) return v;
        StringJoiner j = new StringJoiner(" ");
        for (String w : v.split(" ")) if (!w.isEmpty()) j.add(w);
        return j.toString();
    }

    static boolean enumHas(int e, String v) {
        for (int i = GeneratedDtd.ENUM_OFF[e], end = GeneratedDtd.ENUM_OFF[e + 1]; i < end; i++)
            if (GeneratedDtd.STRS[GeneratedDtd.ENUM_VALS[i]].equals(v)) return true;
        return false;
    }

    static boolean isWs(char[] ch, int start, int len) {
        for (int i = start; i < start + len; i++) {
            char c = ch[i];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return false;
        }
        return true;
    }

    static boolean isWs(String s) {
        return isWs(s.toCharArray(), 0, s.length());
    }

    void contentText(boolean whitespace, boolean cdata) {
        if (depth == 0 || states[depth - 1] == DEAD) return;
        int k = kinds[depth - 1];
        if (k == EMPTY || (k == ELEMENT && (!whitespace || cdata))) {
            states[depth - 1] = DEAD;
            error("character data not allowed here");
        }
    }

    void push(int kind, int state) {
        if (depth == kinds.length) {
            kinds = Arrays.copyOf(kinds, depth * 2);
            states = Arrays.copyOf(states, depth * 2);
        }
        kinds[depth] = kind;
        states[depth++] = state;
    }

    // ---- LexicalHandler / DeclHandler: DOCTYPE and internal subset

    @Override
    public void startDTD(String name, String publicId, String systemId) {
        doctypeName = name;
        inDtd = true;
        shell = publicId == null ? null : SHELL_BY_PUBLIC.get(publicId);
        if (shell == null) error("no compiled DTD for public id '" + publicId + "'");
    }

    @Override public void endDTD() { inDtd = false; }

    private void internalSubset() {
        if (!stop) error("internal DTD subsets are not supported");
        stop = true;
    }

    @Override public void elementDecl(String name, String model) { internalSubset(); }
    @Override public void attributeDecl(String e, String a, String t, String m, String v) { internalSubset(); }
    @Override public void internalEntityDecl(String name, String value) { internalSubset(); }
    @Override public void externalEntityDecl(String name, String p, String s) { internalSubset(); }
    @Override public void startCDATA() { inCdata = true; }
    @Override public void endCDATA() { inCdata = false; }
    @Override public void startEntity(String name) {}
    @Override public void endEntity(String name) {}
    @Override public void comment(char[] ch, int start, int length) {}

    // ---- ContentHandler

    @Override
    public void startElement(String uri, String local, String name, Attributes atts) {
        if (stop) return;
        if (shell == null) {
            if (!seenRoot) error("no DTD found");
            stop = true;
            return;
        }
        seenRoot = true;
        int id = GeneratedDtd.elemId(name);
        boolean declared = id != GeneratedDtd.NONE && shell.kind[id] != 0;
        if (depth == 0) {
            if (!name.equals(doctypeName)) error("root element " + name + " does not match DOCTYPE");
        } else {
            int pk = kinds[depth - 1];
            if ((pk == EMPTY || pk == MIXED || pk == ELEMENT) && states[depth - 1] != DEAD) {
                int next = pk == EMPTY || id == GeneratedDtd.NONE ? -1 : step(states[depth - 1], id);
                if (next >= 0) {
                    states[depth - 1] = next;
                } else {
                    states[depth - 1] = DEAD;
                    error("element " + name + " not allowed here");
                }
            }
        }
        if (!declared) {
            error("no declaration for element " + name);
            push(ANY, DEAD);
            return;
        }
        int al = shell.alist[id], lo = GeneratedDtd.ALIST_OFF[al], hi = GeneratedDtd.ALIST_OFF[al + 1];
        int required = 0;
        for (int a = 0, n = atts.getLength(); a < n; a++) {
            String key = atts.getQName(a);
            int aid = GeneratedDtd.attrId(key);
            int d = -1;
            for (int i = lo; i < hi; i++) {
                if (GeneratedDtd.AD_ATTR[GeneratedDtd.ALIST[i]] == aid) { d = GeneratedDtd.ALIST[i]; break; }
            }
            if (d < 0) { error("no declaration for attribute " + key); continue; }
            int type = GeneratedDtd.AD_TYPE[d];
            String v = type == T_CDATA ? atts.getValue(a) : collapse(atts.getValue(a));
            boolean ok;
            switch (type) {
                case T_CDATA: ok = true; break;
                case T_ID: ok = IS_NAME.matcher(v).matches() && ids.add(v); break;
                case T_IDREF: ok = IS_NAME.matcher(v).matches(); idrefs.add(v); break;
                case T_IDREFS:
                    ok = true;
                    for (String r : v.split(" ")) { ok &= IS_NAME.matcher(r).matches(); idrefs.add(r); }
                    break;
                case T_NMTOKEN: ok = IS_NMTOKEN.matcher(v).matches(); break;
                case T_NMTOKENS:
                    ok = true;
                    for (String t : v.split(" ")) ok &= IS_NMTOKEN.matcher(t).matches();
                    break;
                case 8: case 9: ok = enumHas(GeneratedDtd.AD_ENUM[d], v); break;
                default: ok = false; // ENTITY/ENTITIES: the DTDs declare no unparsed entities
            }
            if (!ok) error("bad value '" + v + "' for attribute " + key);
            int def = GeneratedDtd.AD_DEFAULT[d];
            if (def == D_REQUIRED) required++;
            else if (def == D_FIXED && !GeneratedDtd.STRS[GeneratedDtd.AD_FIXED[d]].equals(v))
                error("attribute " + key + " must be fixed");
        }
        if (required < shell.nreq[id]) error("required attribute missing on " + name);
        push(shell.kind[id], shell.start[id]);
    }

    @Override
    public void endElement(String uri, String local, String name) {
        if (stop || depth == 0) return;
        int k = kinds[--depth], s = states[depth];
        if ((k == ELEMENT || k == MIXED) && s != DEAD && GeneratedDtd.STATE_FINAL[s] == 0)
            error("element content incomplete");
    }

    @Override
    public void characters(char[] ch, int start, int length) {
        if (!stop) contentText(isWs(ch, start, length), inCdata);
    }

    @Override
    public void ignorableWhitespace(char[] ch, int start, int length) {
        characters(ch, start, length);
    }

    /** With the external DTD not read, references to entities it declares arrive here. */
    @Override
    public void skippedEntity(String name) {
        if (stop || shell == null) return;
        int i = Arrays.binarySearch(shell.entityNames, name);
        if (i < 0) {
            error("entity '" + name + "' not defined");
            stop = true;
        } else {
            contentText(isWs(shell.entityValues[i]), false);
        }
    }

    @Override
    public void fatalError(SAXParseException e) throws SAXException {
        throw e;
    }

    @Override
    public void error(SAXParseException e) throws SAXException {
        throw e;
    }

    @Override
    public void endDocument() {
        if (stop) return;
        if (!seenRoot) error("no root element");
        for (String r : idrefs) if (!ids.contains(r)) error("IDREF '" + r + "' has no matching ID");
    }

    // ---- harness

    static XMLReader newReader(DefaultHandler h) throws Exception {
        SAXParserFactory f = SAXParserFactory.newInstance();
        f.setNamespaceAware(false); // qualified names and xmlns attributes, as the DTD declares them
        f.setValidating(false);
        XMLReader r = f.newSAXParser().getXMLReader();
        r.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        r.setFeature("http://xml.org/sax/features/external-general-entities", false);
        r.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        r.setContentHandler(h);
        r.setErrorHandler(h);
        if (h instanceof CompiledValidator) {
            r.setProperty("http://xml.org/sax/properties/lexical-handler", h);
            r.setProperty("http://xml.org/sax/properties/declaration-handler", h);
        }
        return r;
    }

    public static void main(String[] args) throws Exception {
        int nthreads = Integer.parseInt(args[0]);
        int passes = args.length > 1 ? Integer.parseInt(args[1]) : 1;
        boolean verbose = System.getenv("VERBOSE") != null;
        boolean parseOnly = System.getenv("PARSE_ONLY") != null;
        List<String> files = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(System.in))) {
            for (String l; (l = r.readLine()) != null; ) if (!l.isEmpty()) files.add(l);
        }
        for (int pass = 1; pass <= passes; pass++) {
            AtomicInteger next = new AtomicInteger();
            AtomicLong bytes = new AtomicLong();
            AtomicInteger invalid = new AtomicInteger(), errors = new AtomicInteger();
            boolean print = pass == 1;
            CyclicBarrier ready = new CyclicBarrier(nthreads + 1);
            Thread[] th = new Thread[nthreads];
            for (int t = 0; t < nthreads; t++) {
                th[t] = new Thread(() -> {
                    try {
                        CompiledValidator v = new CompiledValidator();
                        XMLReader reader = newReader(parseOnly ? new DefaultHandler() : v);
                        ready.await();
                        for (int i; (i = next.getAndIncrement()) < files.size(); ) {
                            byte[] data = Files.readAllBytes(Paths.get(files.get(i)));
                            bytes.addAndGet(data.length);
                            v.reset(verbose);
                            try {
                                InputSource in = new InputSource(new ByteArrayInputStream(data));
                                in.setSystemId(new File(files.get(i)).toURI().toString());
                                reader.parse(in);
                            } catch (SAXException e) {
                                v.error("not well-formed: " + e.getMessage());
                            }
                            if (v.errors > 0) {
                                invalid.incrementAndGet();
                                errors.addAndGet(v.errors);
                                if (print) {
                                    synchronized (System.out) {
                                        System.out.println("INVALID " + files.get(i) + " " + v.errors);
                                        if (v.messages != null) for (String m : v.messages) System.out.println("  " + m);
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
                th[t].start();
            }
            ready.await();
            long t1 = System.nanoTime();
            for (Thread t : th) t.join();
            double s = (System.nanoTime() - t1) / 1e9;
            System.out.printf(Locale.ROOT,
                "validator=%s pass=%d threads=%d files=%d bytes=%d invalid_files=%d errors=%d "
                + "dtd_load_s=0.000 seconds=%.3f files_per_s=%.0f MB_per_s=%.1f%n",
                parseOnly ? "parse-only-java" : "compiled-java", pass, nthreads, files.size(), bytes.get(),
                invalid.get(), errors.get(), s, files.size() / s, bytes.get() / s / 1e6);
        }
    }
}
