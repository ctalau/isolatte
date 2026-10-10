package org.isolatte;

/** Only readLine()/close() are used by Saxon's reachable line-reader code. */
public final class TextLinesReader extends java.io.BufferedReader {
    private int line;
    public TextLinesReader(java.io.Reader input) { super(input); }
    public TextLinesReader(java.io.Reader input, int size) { super(input, size); }
    public String readLine() throws java.io.IOException {
        String value = super.readLine();
        if (value != null) line++;
        return value;
    }
    public int getLineNumber() { return line; }
    public void setLineNumber(int line) { this.line = line; }
}
