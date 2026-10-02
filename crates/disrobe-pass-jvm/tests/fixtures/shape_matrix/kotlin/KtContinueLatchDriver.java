public class KtContinueLatchDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 12; seed++) {
            KtContinueLatch.continueLatch(seed, out);
            out.append(';');
        }
        System.out.println(out);
    }
}
