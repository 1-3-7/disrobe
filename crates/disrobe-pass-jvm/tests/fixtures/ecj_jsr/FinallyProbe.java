public class FinallyProbe {
    static int log;

    static int guarded(int n) {
        int total = 0;
        try {
            for (int i = 0; i < n; i++) {
                if (i == 7) {
                    throw new IllegalStateException("seven");
                }
                total += i;
            }
        } catch (IllegalStateException e) {
            total = -total;
        } finally {
            log = log * 31 + total;
        }
        return total;
    }

    static int pick(int k) {
        try {
            switch (k) {
                case 0: return 10;
                case 1: return 11;
                default: return k * 2;
            }
        } finally {
            log = log + k;
        }
    }

    public static void main(String[] args) {
        for (int n = 0; n < 10; n++) {
            System.out.println(guarded(n) + " " + pick(n % 3) + " " + log);
        }
    }
}
