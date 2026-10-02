public class KtFinallyBreakDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 6; seed++) {
            KtFinallyBreak.breakThroughFinally(seed, out);
            out.append(';');
        }
        System.out.println(out);
    }
}
