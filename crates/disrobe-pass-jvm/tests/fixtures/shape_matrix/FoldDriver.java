public class FoldDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int a = 0; a < 4; a++) {
            out.append(FoldProbe.plain(a)).append(',');
            out.append(FoldProbe.afterIinc(a)).append(',');
            out.append(FoldProbe.iincInLoop(a)).append(',');
            out.append(FoldProbe.iincOnBranch(a % 2 == 0)).append(',');
            out.append(FoldProbe.iincBeforeReuse(a)).append(';');
        }
        System.out.println(out);
    }
}
