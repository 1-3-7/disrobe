public final class AccumulateProbe {
    static int accumulate(int a, int b, int c, int k) {
        return a + b + c + k;
    }

    static int scale(int a, int b) {
        return a * b + a;
    }

    static long widen(long a, long b) {
        return a * b - a;
    }

    static int negate(int a) {
        return -a + 1;
    }
}

final class CastProbe {
    static int narrow(long a) {
        return (int) (a + 1L);
    }

    static int mixed(int a, int b) {
        return (a - b) * (a + b);
    }
}
