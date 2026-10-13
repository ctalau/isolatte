import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.parsers.XIncludeAwareParserConfiguration;

/** Reference: the same Xerces parse + XInclude on HotSpot. usage: JvmBench N systemId */
public class JvmBench {
    static int parse(String id) throws Exception {
        DOMParser p = new DOMParser(new XIncludeAwareParserConfiguration());
        p.setFeature("http://apache.org/xml/features/xinclude", true);
        p.setFeature("http://apache.org/xml/features/xinclude/fixup-base-uris", false);
        p.parse(id);
        return p.getDocument().getDocumentElement().getTextContent().length();
    }
    public static void main(String[] a) throws Exception {
        int n = Integer.parseInt(a[0]);
        long s = System.nanoTime();
        int len = parse(a[1]);
        long cold = (System.nanoTime() - s) / 1000;
        long[] t = new long[n];
        for (int i = 0; i < n; i++) { long b = System.nanoTime(); parse(a[1]); t[i] = System.nanoTime() - b; }
        java.util.Arrays.sort(t);
        System.out.println("   cold parse: " + cold + " us (text length " + len + ")");
        if (n > 0) System.out.println("   warm parse x" + n + ": median " + t[n / 2] / 1000 + " us, p95 " + t[(int) Math.ceil(n * 0.95) - 1] / 1000 + " us, min " + t[0] / 1000 + " us");
    }
}
