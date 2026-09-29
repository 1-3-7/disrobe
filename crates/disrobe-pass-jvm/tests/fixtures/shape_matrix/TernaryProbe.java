public class TernaryProbe {
    static int calls;

    static int next() {
        calls = calls + 1;
        return calls;
    }

    public static String mixed(int k) {
        StringBuilder sb = new StringBuilder();
        sb.append(next() < 3 ? 'T' : 'F');
        sb.append(next() % 2 == 0 ? "e" : "o");
        sb.append(next() > k + 4);
        int v = k > 2 ? next() : -next();
        sb.append(v).append(',').append(Math.max(next() * 3, k > 1 ? 10 : 20));
        return sb.toString();
    }
}
