public class KtFinallyLoopDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int n = 0; n < 8; n++) {
            out.append(KtFinallyLoop.finallyInLoop(n)).append(',');
        }
        System.out.println(out);
    }
}
