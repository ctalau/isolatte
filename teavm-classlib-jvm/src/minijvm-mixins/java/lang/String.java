package java.lang;

import jdk.internal.mixin.MixinProvided;
import jdk.internal.mixin.MixinReplace;

/**
 * Mixin: TeaVM's String has no character storage; each backend supplies it through natives.
 * miniJVM's C code creates and reads strings through these four fields, so the natives get
 * bodies over them.
 */
public final class String {
    private char[] value;
    private int count;
    private int offset;
    private int hash;

    @MixinReplace
    private void initWithEmptyChars() {
        value = new char[0];
    }

    @MixinReplace
    private void borrowChars(String other) {
        value = other.value;
        offset = other.offset;
        count = other.count;
    }

    @MixinReplace
    private void initWithCharArray(char[] chars, int off, int len) {
        value = new char[len];
        System.arraycopy(chars, off, value, 0, len);
        count = len;
    }

    @MixinReplace
    private void takeCharArray(char[] chars) {
        value = chars;
        count = chars.length;
    }

    @MixinReplace
    private int charactersLength() {
        return count;
    }

    @MixinReplace
    private char charactersGet(int index) {
        return value[offset + index];
    }

    @MixinReplace
    private void copyCharsToArray(int begin, char[] dst, int dstBegin, int length) {
        System.arraycopy(value, offset + begin, dst, dstBegin, length);
    }

    @MixinReplace
    private char[] fastCharArray() {
        if (offset == 0 && count == value.length) {
            return value;
        }
        char[] r = new char[count];
        System.arraycopy(value, offset, r, 0, count);
        return r;
    }

    @MixinReplace
    public String intern() {
        return intern0();
    }

    private native String intern0();

    @MixinProvided
    public String replace(char oldChar, char newChar) {
        return null;
    }

    @MixinProvided
    public boolean startsWith(String prefix) {
        return false;
    }

    @MixinProvided
    public String substring(int beginIndex) {
        return null;
    }

    /** TeaVM's StringInfo is retargeted to String (see TeaVMRenamer). */
    String ci$getStringObject() {
        return this;
    }
}
