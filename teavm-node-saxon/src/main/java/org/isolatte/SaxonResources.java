package org.isolatte;

import org.teavm.classlib.ResourceSupplier;
import org.teavm.classlib.ResourceSupplierContext;

/** Embed Saxon's lookup tables in the generated module, without host file access. */
public final class SaxonResources implements ResourceSupplier {
    public String[] supplyResources(ResourceSupplierContext context) {
        return new String[] {
            "net/sf/saxon/data/casevariants.xml", "net/sf/saxon/data/categories.xml",
            "net/sf/saxon/data/unicodeBlocks.xml", "net/sf/saxon/data/entities.txt"
        };
    }
    public static java.io.InputStream open(String name) {
        return SaxonResources.class.getClassLoader().getResourceAsStream("net/sf/saxon/data/" + name);
    }
}
