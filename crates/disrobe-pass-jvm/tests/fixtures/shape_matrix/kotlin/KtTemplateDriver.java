public class KtTemplateDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int a = -1; a < 4; a++) {
            out.append(KtTemplate.describe(a, a * 5000000000L, a / 4.0, (char) ('p' + a), a % 2 == 0)).append('|');
            out.append(KtTemplate.nested(a)).append('|');
            out.append(KtTemplate.withNull(a)).append('|');
            out.append(KtTemplate.loopConcat(a)).append(';');
        }
        System.out.println(out);
    }
}
