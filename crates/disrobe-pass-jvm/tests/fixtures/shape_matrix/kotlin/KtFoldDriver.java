public class KtFoldDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int a = 0; a < 5; a++) {
            out.append(KtFold.afterIncrement(a)).append(',');
            out.append(KtFold.incrementAsValue(a)).append(',');
            out.append(KtFold.incrementInLoop(a)).append(',');
            out.append(KtFold.incrementOnBranch(a % 2 == 0)).append(',');
            out.append(KtFold.foldAcross(a)).append(';');
        }
        System.out.println(out);
    }
}
