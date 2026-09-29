public class TernaryDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = 0; k < 5; k++) {
            out.append(TernaryProbe.mixed(k)).append(';');
        }
        out.append(TernaryProbe.calls);
        System.out.println(out);
    }
}
