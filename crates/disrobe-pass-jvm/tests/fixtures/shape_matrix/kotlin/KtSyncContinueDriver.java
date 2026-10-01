public class KtSyncContinueDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int n = 0; n < 8; n++) {
            out.append(KtSyncContinue.syncContinue(n)).append(',');
        }
        System.out.println(out);
    }
}
