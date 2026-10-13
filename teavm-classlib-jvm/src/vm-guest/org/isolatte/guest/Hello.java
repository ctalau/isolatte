package org.isolatte.guest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Smoke test: strings, collections, lambdas, exceptions, reflection names, on TeaVM's java.*. */
public final class Hello {
    public static void main(String[] args) {
        System.out.println("hello from " + Object.class.getName() + " = " + new Object().getClass());
        List<String> l = new ArrayList<>();
        for (String a : args) {
            l.add(a.toUpperCase());
        }
        Map<String, Integer> m = new HashMap<>();
        l.forEach(s -> m.merge(s, 1, Integer::sum));
        System.out.println("args " + l + " counts " + m + " pi " + Math.PI + " " + 1.5f + " " + Long.MAX_VALUE);
        try {
            Object o = "x";
            Integer i = (Integer) o;
            System.out.println(i);
        } catch (ClassCastException e) {
            System.out.println("caught " + e);
        }
        try {
            int[] a = new int[1];
            a[2] = 1;
        } catch (ArrayIndexOutOfBoundsException e) {
            StackTraceElement top = e.getStackTrace()[0];
            System.out.println("caught " + e.getClass().getSimpleName() + " at " + top);
        }
        System.out.println(String.format("%05d|%s|%.3f", 42, "fmt", 2.5));
        StringBuilder sb = new StringBuilder();
        sb.append('c').append(1).append(2L).append(true);
        System.out.println(sb.reverse());
    }
}
