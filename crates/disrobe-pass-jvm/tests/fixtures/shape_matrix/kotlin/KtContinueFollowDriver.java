public class KtContinueFollowDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int seed = 0; seed < 8; seed++) {
            KtContinueFollow.continueFollow(seed, out);
            out.append(';');
        }
        System.out.println(out);
    }
}
