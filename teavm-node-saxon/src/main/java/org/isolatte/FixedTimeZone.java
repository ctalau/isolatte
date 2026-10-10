package org.isolatte;

/** Saxon constructs SimpleTimeZone only with a fixed offset and an ID. */
public final class FixedTimeZone extends java.util.TimeZone {
    private int offset;
    public FixedTimeZone(int offset, String id) { this.offset = offset; setID(id); }
    public int getOffset(int era, int year, int month, int day, int dayOfWeek, int milliseconds) { return offset; }
    public void setRawOffset(int offset) { this.offset = offset; }
    public int getRawOffset() { return offset; }
    public boolean useDaylightTime() { return false; }
    public boolean inDaylightTime(java.util.Date date) { return false; }
}
