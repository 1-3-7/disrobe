public class FinallyJoinProbe {
    static int log;

    static int continuing(int n) {
        int t = 0;
        for (int i = 0; i < n; i++) {
            try {
                if (i % 3 == 0) {
                    continue;
                }
                t += i;
            } finally {
                if (i > 2) {
                    log ^= t;
                }
            }
        }
        return t;
    }
}
