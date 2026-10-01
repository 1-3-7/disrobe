public class KtCountLoopDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 12; seed++) {
            out.append(KtCountLoop.countUntilReturn(seed)).append(',');
            out.append(KtCountLoop.countUntilBreak(seed, seed % 5 + 1)).append(',');
            out.append(KtCountLoop.countUntilThrow(seed)).append(';');
        }
        System.out.println(out);
    }
}
