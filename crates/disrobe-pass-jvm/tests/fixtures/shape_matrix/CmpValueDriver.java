public class CmpValueDriver {
    public static void main(String[] args) {
        long[] longs = {Long.MIN_VALUE, -1L, 0L, 1L, Long.MAX_VALUE};
        double[] doubles = {Double.NaN, Double.NEGATIVE_INFINITY, -0.0, 0.0, 1.5};
        StringBuilder out = new StringBuilder();
        for (long a : longs) {
            for (long b : longs) {
                out.append(CmpValueProbe.longOrder(a, b)).append(CmpValueProbe.longOrderPlusOne(a, b)).append(' ');
            }
        }
        out.append('|');
        for (double a : doubles) {
            for (double b : doubles) {
                out.append(CmpValueProbe.floatLow((float) a, (float) b)).append(',');
                out.append(CmpValueProbe.floatHigh((float) a, (float) b)).append(',');
                out.append(CmpValueProbe.doubleLow(a, b)).append(',');
                out.append(CmpValueProbe.doubleHigh(a, b)).append(' ');
            }
        }
        System.out.println(out);
    }
}
