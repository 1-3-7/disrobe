public class LongCompareProbe {
    public static int ordered(long a, long b) {
        return a < b ? -1 : (a == b ? 0 : 1);
    }

    public static boolean atLeast(long a, long b) {
        return a >= b;
    }

    public static int boxed(Long a, Long b) {
        return a.compareTo(b);
    }

    public static int library(long a, long b) {
        return Long.compare(a, b);
    }

    public static int sign(long a, long b) {
        int r = 0;
        if (a > b) {
            r = 1;
        } else if (a < b) {
            r = -1;
        }
        return r;
    }

    public static int countBelow(long[] values, long limit) {
        int n = 0;
        for (int i = 0; i < values.length; i++) {
            if (values[i] <= limit) {
                n++;
            }
        }
        return n;
    }
}
