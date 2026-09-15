public final class ParamProbe {
    static int paramReassign(int a, int flag) {
        if (flag > 0) {
            a = 7;
        }
        return a + 1;
    }

    static int paramConstChain(int a, int b) {
        a = 11;
        b = a + b;
        return a + b;
    }

    static int paramTextLength(String s, int flag) {
        String t = s;
        if (flag > 0) {
            t = "seven";
        }
        return t.length();
    }
}

final class TempProbe {
    static long wideTemp(long a, int flag) {
        long t = 3L;
        if (flag > 0) {
            t = a * 5L;
        }
        return t + a;
    }

    static int intTemp(int a, int flag) {
        int t;
        if (flag > 0) {
            t = 7;
        } else {
            t = a * 2;
        }
        return t + a;
    }

    static int textTemp(String s, int flag) {
        String t;
        if (flag > 0) {
            t = s.trim();
        } else {
            t = s.toUpperCase();
        }
        return t.length();
    }
}

final class LocalProbe {
    static int branchConst(int a, boolean flag) {
        int t;
        if (flag) {
            t = 7;
        } else {
            t = a * 2;
        }
        return t + a;
    }
}
