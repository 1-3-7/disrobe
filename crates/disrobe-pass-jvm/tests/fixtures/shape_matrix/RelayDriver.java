public class RelayDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int x = -2; x < 5; x++) {
            out.append(RelayProbe.relay(x)).append(';');
        }
        System.out.println(out);
    }
}
