public class FinallyBranchExitDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = -1; k < 6; k++) {
            FinallyBranchExitProbe.voidExits(k);
            out.append(FinallyBranchExitProbe.threeReturns(k)).append(' ');
            out.append(FinallyBranchExitProbe.log).append(' ');
            out.append(FinallyBranchExitProbe.after).append(';');
        }
        System.out.println(out);
    }
}
