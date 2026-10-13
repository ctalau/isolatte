package org.isolatte.bench;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Library-heavy CPU work, timed inside the guest: integer loops, a HashMap keyed by built strings,
 * StringBuilder/String searching, and a sort with a lambda comparator. Prints one line per round.
 */
public final class CpuBench {
    public static void main(String[] args) {
        int rounds = args.length > 0 ? Integer.parseInt(args[0]) : 5;
        int size = args.length > 1 ? Integer.parseInt(args[1]) : 20000;
        long check = 0;
        for (int r = 0; r < rounds; r++) {
            long t0 = System.nanoTime();
            check += round(size);
            long t1 = System.nanoTime();
            System.out.println("round " + r + ": " + (t1 - t0) / 1000000 + " ms");
        }
        System.out.println("check " + check);
    }

    private static long round(int size) {
        long sum = 0;
        // 1. sieve
        boolean[] composite = new boolean[size * 10];
        for (int i = 2; i < composite.length; i++) {
            if (!composite[i]) {
                sum += i;
                for (int j = i * 2; j < composite.length; j += i) {
                    composite[j] = true;
                }
            }
        }
        // 2. HashMap with string keys
        Map<String, Integer> map = new HashMap<>();
        for (int i = 0; i < size; i++) {
            map.put("key" + i, i);
        }
        for (int i = 0; i < size; i++) {
            sum += map.get("key" + (size - 1 - i));
        }
        // 3. StringBuilder and searching
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; i++) {
            sb.append(i % 10).append(',');
        }
        String s = sb.toString();
        for (int from = 0; (from = s.indexOf("9,", from)) >= 0; from++) {
            sum++;
        }
        // 4. sort with a comparator lambda
        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            list.add((i * 7919) % size);
        }
        Collections.sort(list, (a, b) -> Integer.compare(b, a));
        sum += list.get(0);
        return sum;
    }

    private CpuBench() {
    }
}
