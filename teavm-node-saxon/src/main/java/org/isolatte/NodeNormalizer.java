package org.isolatte;

import org.teavm.jso.JSBody;

/** Use ECMAScript's Unicode normalization, preserving the requested form. */
public final class NodeNormalizer {
    public enum Form { NFC, NFD, NFKC, NFKD }
    public static String normalize(CharSequence text, Form form) {
        return normalizeString(text.toString(), form.name());
    }
    @JSBody(params = {"text", "form"}, script = "return text.normalize(form);")
    private static native String normalizeString(String text, String form);
}
