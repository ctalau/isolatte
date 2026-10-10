package org.isolatte;

import org.teavm.jso.JSBody;

/** Node supplies SHA-256 for Saxon's stylesheet checksums. */
public final class NodeDigest {
    private final StringBuilder input = new StringBuilder();
    private String digest;
    public void update(int value) { input.append(value); }
    public void update(String value) { input.append(value); }
    public String getDigest() {
        if (digest == null) digest = sha256(input.toString());
        return digest;
    }
    @JSBody(params = "value", script = "return require('node:crypto').createHash('sha256').update(value, 'utf8').digest('hex');")
    private static native String sha256(String value);
}
