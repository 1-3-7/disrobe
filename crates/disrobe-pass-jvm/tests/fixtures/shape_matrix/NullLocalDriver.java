public class NullLocalDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = 0; k < 6; k++) {
            out.append(NullLocalProbe.label(k)).append(',').append(NullLocalProbe.parity(k)).append(';');
        }
        System.out.println(out);
    }
}
