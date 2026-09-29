public class FlagValueDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int a = -4; a < 8; a++) {
            int b = 3 - a;
            FlagValueProbe.nestedField(a, b);
            out.append(FlagValueProbe.flagSum(a)).append(',');
            out.append(FlagValueProbe.flagSwitch(a)).append(',');
            out.append(FlagValueProbe.dispatch(new int[] {a})).append(',');
            out.append(FlagValueProbe.nested(a, b)).append(',');
            out.append(FlagValueProbe.seen).append(',');
            out.append(FlagValueProbe.flags(a)).append(',');
            out.append(FlagValueProbe.arguments(a, b)).append(';');
        }
        System.out.println(out);
    }
}
