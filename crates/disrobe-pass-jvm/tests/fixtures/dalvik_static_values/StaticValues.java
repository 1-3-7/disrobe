public class StaticValues {
    static String trace = "";
    static String quoted = "café \"q\" \\ tab\tend\n";
    static int n = 3;
    static int negative = -70000;
    static int untouched;
    static final long K = 5L;
    static long wide = -1234567890123L;
    static char letter = 'x';
    static char newline = '\n';
    static boolean flag = true;
    static float ratio = 2.5f;
    static float negativeZero = -0.0f;
    static double tiny = -1.0e-3;
    static double huge = 1e300;
    static byte small = -7;
    static short medium = 300;
    static String none = null;
    static Object nothing;
    static StringBuilder log = new StringBuilder();
    static int computed;
    static int last;

    static {
        log.append(trace).append(n).append(':').append(K);
        computed = n * 7 + (int) wide;
        n = n + 1;
        trace = trace + "clinit";
    }

    public static class Constants {
        static int answer = 42;
        static String label = "constants";
        static long mask = 0xFFFF_0000_FFFFL;
        static boolean off;
        static double half = 0.5;
    }

    public static void main(String[] args) {
        System.out.println(trace);
        System.out.println(quoted.hashCode());
        System.out.println(quoted.length());
        System.out.println(n);
        System.out.println(negative);
        System.out.println(untouched);
        System.out.println(K);
        System.out.println(wide);
        System.out.println(letter);
        System.out.println(newline * 3);
        System.out.println(flag);
        System.out.println(ratio);
        System.out.println(1.0f / negativeZero);
        System.out.println(tiny);
        System.out.println(huge);
        System.out.println(small);
        System.out.println(medium);
        System.out.println(none);
        System.out.println(nothing);
        System.out.println(log);
        System.out.println(computed);
        System.out.println(last);
        System.out.println(Constants.answer);
        System.out.println(Constants.label);
        System.out.println(Constants.mask);
        System.out.println(Constants.off);
        System.out.println(Constants.half);
    }
}
