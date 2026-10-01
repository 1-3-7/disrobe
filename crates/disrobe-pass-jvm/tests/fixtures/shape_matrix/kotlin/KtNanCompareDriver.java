public class KtNanCompareDriver {
    public static void main(String[] args) {
        double[] values = {Double.NaN, Double.NEGATIVE_INFINITY, -1.5, -0.0, 0.0, 2.25, Double.POSITIVE_INFINITY};
        StringBuilder out = new StringBuilder();
        for (double a : values) {
            for (double b : values) {
                out.append(KtNanCompare.doubleFlags(a, b)).append(' ');
                out.append(KtNanCompare.floatFlags((float) a, (float) b)).append(' ');
                out.append(KtNanCompare.lessAsValue(a, b) ? 'y' : 'n').append(' ');
                out.append(KtNanCompare.order(a, b)).append(' ');
                out.append(KtNanCompare.smaller(a, b)).append(',');
            }
            out.append(';');
        }
        System.out.println(out);
    }
}
