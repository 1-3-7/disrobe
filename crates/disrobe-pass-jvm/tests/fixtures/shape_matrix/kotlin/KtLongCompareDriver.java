public class KtLongCompareDriver {
    public static void main(String[] args) {
        long[] values = {Long.MIN_VALUE, -4294967296L, -1L, 0L, 1L, 4294967296L, Long.MAX_VALUE};
        StringBuilder out = new StringBuilder();
        for (long a : values) {
            for (long b : values) {
                out.append(KtLongCompare.order(a, b)).append(' ');
                out.append(KtLongCompare.orderPlus(a, b)).append(' ');
                out.append(KtLongCompare.asConditions(a, b)).append(' ');
                out.append(KtLongCompare.intOrder(a, b)).append(',');
            }
            out.append(';');
        }
        System.out.println(out);
    }
}
