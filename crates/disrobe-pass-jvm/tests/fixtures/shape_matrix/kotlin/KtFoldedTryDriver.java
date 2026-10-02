public class KtFoldedTryDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = -4; k < 6; k++) {
            out.append(KtFoldedTry.deadArmAtTryStart(k)).append(',');
        }
        System.out.println(out);
    }
}
