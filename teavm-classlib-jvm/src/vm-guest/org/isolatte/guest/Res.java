package org.isolatte.guest;

import java.util.HashMap;
import java.util.Map;

/**
 * Decodes the metadata TeaVM's generators produced at build time (see MetadataBaker). TeaVM's
 * compiler embeds the same data as JavaScript/C literals; here it is a string constant in the
 * method that used to be the metadata native.
 */
public final class Res {
    /** Creates the object resources (generated per Resource interface by the builder). */
    public interface Factory {
        Object create(int type, Map<String, Object> fields);
    }

    private final String s;
    private final Factory factory;
    private int pos;

    private Res(String s, Factory factory) {
        this.s = s;
        this.factory = factory;
    }

    public static Object decode(String s, Factory factory) {
        return new Res(s, factory).value();
    }

    private Object value() {
        char tag = s.charAt(pos++);
        switch (tag) {
            case 'N':
                return null;
            case 'S':
                return new StrRes(string());
            case 's':
                return string();
            case 'I':
                return new IntRes((int) number());
            case 'i':
                return Integer.valueOf((int) number());
            case 'z':
                return Boolean.valueOf(number() != 0);
            case 'c':
                return Character.valueOf((char) number());
            case 'b':
                return Byte.valueOf((byte) number());
            case 'h':
                return Short.valueOf((short) number());
            case 'l':
                return Long.valueOf(number());
            case 'f':
                return Float.valueOf(Float.intBitsToFloat((int) number()));
            case 'd':
                return Double.valueOf(Double.longBitsToDouble(number()));
            case 'M': {
                int n = (int) number();
                MapRes map = new MapRes();
                for (int i = 0; i < n; i++) {
                    String key = string();
                    map.put(key, value());
                }
                return map;
            }
            case 'A': {
                int n = (int) number();
                ArrRes arr = new ArrRes();
                for (int i = 0; i < n; i++) {
                    arr.addValue(value());
                }
                return arr;
            }
            case 'O': {
                int type = (int) number();
                int n = (int) number();
                Map<String, Object> fields = new HashMap<>();
                for (int i = 0; i < n; i++) {
                    String key = string();
                    fields.put(key, value());
                }
                return factory.create(type, fields);
            }
            default:
                throw new IllegalStateException("bad metadata tag " + tag + " at " + (pos - 1));
        }
    }

    private long number() {
        int end = s.indexOf(';', pos);
        long v = Long.parseLong(s.substring(pos, end));
        pos = end + 1;
        return v;
    }

    private String string() {
        int colon = s.indexOf(':', pos);
        int len = Integer.parseInt(s.substring(pos, colon));
        String r = s.substring(colon + 1, colon + 1 + len);
        pos = colon + 1 + len;
        return r;
    }
}
