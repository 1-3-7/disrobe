public class KtWhenDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        int[] keys = {-1000, -101, -5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 70, 101, 700, 1000};
        for (int k : keys) {
            out.append(KtWhen.shared(k)).append(',');
            out.append(KtWhen.sharedValue(k)).append(',');
            out.append(KtWhen.ranges(k)).append(',');
            out.append(KtWhen.sparse(k)).append(',');
            out.append(KtWhen.oneRange(k)).append(';');
        }
        System.out.println(out);
    }
}
