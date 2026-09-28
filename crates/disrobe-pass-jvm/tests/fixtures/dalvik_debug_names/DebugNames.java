public class DebugNames {
    static int scale(int count, int factor) {
        int total = 0;
        for (int step = 0; step < count; step++) {
            total += step * factor;
        }
        return total;
    }

    static String describe(int value, boolean verbose) {
        String label = value > 10 ? "big" : "small";
        if (verbose) {
            long widened = value * 3L;
            return label + ":" + widened;
        }
        double half = value / 2.0;
        return label + "/" + half;
    }

    public static void main(String[] args) {
        for (int k = -2; k < 14; k += 3) {
            System.out.println(scale(k, 3) + " " + describe(k, k % 2 == 0));
        }
    }
}
