public class LongCompareDriver {
    public static void main(String[] args) {
        long[] values = {Long.MIN_VALUE, -5L, 0L, 1L, 4294967296L, Long.MAX_VALUE};
        StringBuilder out = new StringBuilder();
        for (long a : values) {
            for (long b : values) {
                out.append(LongCompareProbe.ordered(a, b));
                out.append(LongCompareProbe.atLeast(a, b) ? 'y' : 'n');
                out.append(LongCompareProbe.boxed(a, b));
                out.append(LongCompareProbe.library(a, b));
                out.append(LongCompareProbe.sign(a, b)).append(' ');
            }
            out.append(LongCompareProbe.countBelow(values, a)).append(';');
        }
        System.out.println(out);
    }
}
