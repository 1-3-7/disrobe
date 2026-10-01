public class KtWhenStringDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = -4; k < 8; k++) {
            out.append(KtWhenString.byName(k)).append(',');
        }
        System.out.println(out);
    }
}
