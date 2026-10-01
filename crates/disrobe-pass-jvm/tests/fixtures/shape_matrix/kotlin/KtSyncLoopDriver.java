public class KtSyncLoopDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int n = 0; n < 8; n++) {
            out.append(KtSyncLoop.syncSum(n)).append(',');
            out.append(KtSyncLoop.syncBreak(n, 3)).append(',');
            out.append(KtSyncLoop.syncValue(n)).append(';');
        }
        System.out.println(out);
    }
}
