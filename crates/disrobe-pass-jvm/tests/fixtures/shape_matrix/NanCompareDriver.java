public class NanCompareDriver {
    public static void main(String[] args) {
        double[] ds = {Double.NaN, -1.5, 0.0, 2.0, Double.POSITIVE_INFINITY};
        StringBuilder out = new StringBuilder();
        for (double a : ds) {
            for (double b : ds) {
                out.append(NanCompareProbe.doubles(a, b)).append(' ');
                out.append(NanCompareProbe.floats((float) a, (float) b)).append(' ');
                out.append(NanCompareProbe.below(a, b) ? 'y' : 'n');
                out.append(NanCompareProbe.notAtLeast((float) a, (float) b) ? 'y' : 'n').append(',');
            }
            out.append(NanCompareProbe.halvings(a)).append(';');
        }
        System.out.println(out);
    }
}
