public class FinallyExitDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int n = -1; n < 9; n++) {
            out.append(FinallyExitProbe.returning(n)).append(' ').append(FinallyExitProbe.log).append(' ');
            out.append(FinallyExitProbe.nested(n)).append(' ').append(FinallyExitProbe.log).append(' ');
            out.append(FinallyExitProbe.breaking(n)).append(' ').append(FinallyExitProbe.log).append(' ');
            out.append(FinallyExitProbe.caught(n)).append(' ').append(FinallyExitProbe.log).append(' ');
            out.append(FinallyExitProbe.switching(n)).append(' ').append(FinallyExitProbe.log).append(' ');
            FinallyExitProbe.returningVoid(n);
            out.append(FinallyExitProbe.log).append(';');
        }
        System.out.println(out);
    }
}
