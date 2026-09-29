import java.util.Arrays;
import java.util.concurrent.Callable;

public class LiftProbes {
    static int counter;
    static String trace;
    static final Object LOCK = new Object();

    static int tick(String tag) {
        trace = trace + tag;
        counter = counter + 1;
        return counter;
    }

    static int combine(int left, int right) {
        return left * 7 - right;
    }

    static String arrays(int seed) {
        int[] picked = {seed, seed + 1, seed * 2};
        int[] spread = {seed, seed + 1, seed + 2, seed + 3, seed + 4, seed + 5, seed * 9};
        String[] words = {"w" + seed, "v", null};
        int[] table = {3, 1, 4, 1, 5, 9, 2, 6, -5, 65536};
        long[] wide = {1L << 40, -7L, 3L};
        char[] letters = {'d', 'e', 'x', '\'', '\\', '\u00e9'};
        byte[] small = {-1, 2, 127, -128};
        short[] shorts = {-300, 300};
        boolean[] flags = {true, false, true};
        float[] ratios = {0.5f, -2.25f};
        double[] halves = {0.5, -1e300};
        int sum = 0;
        for (int i = 0; i < table.length; i++) {
            sum += table[i] * seed;
        }
        int codes = 0;
        for (int i = 0; i < letters.length; i++) {
            codes = codes * 31 + letters[i];
        }
        return Arrays.toString(picked) + Arrays.toString(spread) + Arrays.toString(words) + sum
                + Arrays.toString(wide) + codes + Arrays.toString(small) + Arrays.toString(shorts)
                + Arrays.toString(flags) + Arrays.toString(ratios) + Arrays.toString(halves);
    }

    static String halvings(int start) {
        int n = start;
        int steps = 0;
        while ((n = n / 2) > 1) {
            steps++;
            if (steps > 40) {
                return "runaway";
            }
        }
        return steps + ":" + n;
    }

    static String reads(int limit) {
        trace = "";
        int value;
        int sum = 0;
        while ((value = tick("r")) % 4 != 0) {
            sum += value;
            if (sum > limit) {
                return "runaway:" + sum;
            }
        }
        return sum + ":" + value + ":" + trace;
    }

    static String polls() {
        trace = "";
        int polled = 0;
        while (tick("w") % 5 != 0) {
            polled += 2;
        }
        return polled + ":" + trace;
    }

    static String strings() {
        String text = "caf\u00e9|\u03c0|tab\there|nul\u0000|\u0001|q\"b\\s|\ud83d\ude00|\u2028|\uffff|\r\n";
        StringBuilder units = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            units.append(Integer.toHexString(text.charAt(i))).append(' ');
        }
        return units.toString();
    }

    static String order() {
        trace = "";
        int a = tick("a");
        int b = tick("b");
        int c = tick("c");
        int mixed = c * 100 + b * 10 + a;
        int first = tick("x");
        int paired = combine(tick("y"), first);
        return mixed + ":" + paired + ":" + trace;
    }

    static String temporaries(int count) {
        int total = 0;
        for (int i = 0; i < count; i++) {
            total += i * count;
        }
        String label = "n" + total;
        long wide = (long) count << 33;
        StringBuilder out = new StringBuilder(label);
        double ratio = total / 3.0;
        out.append(':').append(wide).append(':').append(ratio);
        Object boxed = count > 2 ? (Object) Integer.valueOf(count) : (Object) "small";
        return out.append(':').append(boxed).toString();
    }

    static String chain(String key, int mode) {
        String out;
        if (key.equals("a")) {
            out = "A" + mode;
        } else if (key.equals("bb")) {
            out = "B";
        } else {
            out = key.toUpperCase();
        }
        return out + mode;
    }

    static String fallback(String first, String second) {
        try {
            return "p" + Integer.parseInt(first);
        } catch (NumberFormatException outer) {
            try {
                return "q" + Integer.parseInt(second);
            } catch (NumberFormatException inner) {
                return inner.getMessage().length() + ":" + outer.getMessage().length();
            }
        }
    }

    static String settle(int mode) {
        StringBuilder log = new StringBuilder();
        try {
            if (mode == 0) {
                return "zero";
            }
            log.append(Integer.parseInt(mode == 1 ? "x" : "7"));
        } catch (NumberFormatException e) {
            log.append("bad");
            return log.toString();
        } finally {
            log.append("|f");
            trace = trace + log;
        }
        return log.toString();
    }

    static int rescue(String first, String second) {
        int total = 0;
        try {
            total = Integer.parseInt(first);
        } catch (NumberFormatException outer) {
            try {
                total = Integer.parseInt(second) * 2;
            } catch (NumberFormatException nested) {
                total = -1;
            }
            total += 100;
        }
        return total;
    }

    static int keyed(String key) {
        int result = 0;
        switch (key) {
            case "alpha":
                result = 1;
                break;
            case "beta":
                result = 2;
            case "Aa":
                result += 30;
                break;
            case "BB":
                result = 4;
                break;
            default:
                result = key.length() * 100;
        }
        return result;
    }

    static String spelled(String key) {
        String out = "";
        switch (key) {
            case "one":
                out = "1";
                break;
            case "two":
                out = "2";
            case "three":
                out = out + "3";
                break;
            default:
                out = "?";
        }
        return out;
    }

    static String guarded(int n) {
        int sum = 0;
        synchronized (LOCK) {
            for (int i = 0; i < n; i++) {
                sum += i;
            }
            counter += sum + (Thread.holdsLock(LOCK) ? 1000 : 0);
        }
        return sum + ":" + counter + ":" + Thread.holdsLock(LOCK);
    }

    static int guardedReturn(int[] cells, int index) {
        synchronized (cells) {
            if (index < 0) {
                return Thread.holdsLock(cells) ? -1 : -2;
            }
            cells[index] = cells[index] + 1;
            return cells[index] + (Thread.holdsLock(cells) ? 100 : 0);
        }
    }

    static int looped(int n) {
        int total = 0;
        for (int i = 0; i < n; i++) {
            synchronized (LOCK) {
                total += Thread.holdsLock(LOCK) ? i : -i;
                if (total > 20) {
                    break;
                }
            }
            tick("l");
        }
        return total;
    }

    static int drained(int n) {
        int total = 0;
        for (int i = 0; i < n; i++) {
            total += i;
            if (total > 20) {
                tick("b");
                break;
            }
            tick("p");
        }
        return total;
    }

    public abstract static class Worker implements Callable<Integer>, Runnable {
        public final void run() {
            try {
                call();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    public static class Counting extends Worker {
        int total;

        public Integer call() {
            total += 5;
            return total;
        }
    }

    static String workers() throws Exception {
        Counting counting = new Counting();
        Runnable runnable = counting;
        runnable.run();
        Callable<Integer> callable = counting;
        return callable.call() + ":" + counting.total;
    }

    public static void main(String[] args) throws Exception {
        trace = "";
        for (int seed = -1; seed < 3; seed++) {
            System.out.println(arrays(seed));
        }
        for (int start = 0; start < 70; start += 13) {
            System.out.println(halvings(start));
        }
        for (int round = 0; round < 3; round++) {
            System.out.println(reads(1000));
        }
        System.out.println(polls());
        System.out.println(strings());
        System.out.println(order());
        System.out.println(workers());
        for (int count = 0; count < 5; count += 2) {
            System.out.println(temporaries(count));
        }
        for (int round = 0; round < 3; round++) {
            System.out.println(chain(round == 0 ? "a" : round == 1 ? "bb" : "k" + round, round));
        }
        System.out.println(fallback("4", "x"));
        System.out.println(fallback("y", "5"));
        System.out.println(fallback("zz", "wwww"));
        for (int mode = 0; mode < 3; mode++) {
            System.out.println(settle(mode) + " " + trace);
        }
        System.out.println(rescue("4", "x") + ":" + rescue("y", "5") + ":" + rescue("zz", "w"));
        for (String key : new String[] {"alpha", "beta", "Aa", "BB", "one", "two", "three", ""}) {
            System.out.println(keyed(key) + ":" + spelled(key));
        }
        System.out.println(guarded(5));
        int[] cells = {4, 5};
        System.out.println(guardedReturn(cells, 1) + ":" + guardedReturn(cells, -1));
        System.out.println(looped(3) + ":" + looped(10) + ":" + drained(3) + ":" + drained(10) + ":" + trace);
    }
}
