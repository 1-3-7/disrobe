public class CompoundTernaryDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = -2; k < 5; k++) {
            int b = 2 - k;
            out.append(CompoundTernaryProbe.both(k, b)).append(',');
            out.append(CompoundTernaryProbe.either(k, b)).append(',');
            out.append(CompoundTernaryProbe.guarded(k > 0 ? "s" + k : null, k)).append(',');
            out.append(CompoundTernaryProbe.grouped(k, b, k - 1)).append(',');
            out.append(CompoundTernaryProbe.counted(k)).append(';');
        }
        out.append(CompoundTernaryProbe.calls);
        System.out.println(out);
    }
}
