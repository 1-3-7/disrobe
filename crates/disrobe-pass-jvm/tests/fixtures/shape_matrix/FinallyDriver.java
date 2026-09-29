public class FinallyDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int n = 0; n < 10; n++) {
            out.append(FinallyProbe.guarded(n)).append(' ');
            out.append(FinallyProbe.pick(n % 4)).append(' ');
            out.append(FinallyProbe.log).append(';');
        }
        System.out.println(out);
    }
}
