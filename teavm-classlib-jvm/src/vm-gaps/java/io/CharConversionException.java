package java.io;

/**
 * Missing from TeaVM's java.io; Xerces' MalformedByteSequenceException extends it. Same API as
 * Java SE's.
 */
public class CharConversionException extends IOException {
    public CharConversionException() {
    }

    public CharConversionException(String message) {
        super(message);
    }
}
