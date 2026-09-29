public class FinallyJoinDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int n = -1; n < 9; n++) {
            out.append(FinallyJoinProbe.continuing(n)).append(' ').append(FinallyJoinProbe.log).append(';');
        }
        System.out.println(out);
    }
}
