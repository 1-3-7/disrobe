public class KtFinallyDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int a = -1; a < 7; a++) {
            try {
                out.append(KtFinally.returnInTry(a));
            } catch (ArithmeticException e) {
                out.append("div");
            }
            out.append(',').append(KtFinally.getCounter()).append(',');
            try {
                out.append(KtFinally.nestedFinally(a, a - 1));
            } catch (ArithmeticException e) {
                out.append("div");
            }
            out.append(',').append(KtFinally.tryAsValue(a)).append(',');
            out.append(KtFinally.getCounter()).append(';');
        }
        System.out.println(out);
    }
}
