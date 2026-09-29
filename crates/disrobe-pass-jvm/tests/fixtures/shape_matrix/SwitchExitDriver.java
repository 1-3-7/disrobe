public class SwitchExitDriver {
    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int k = 0; k < 4; k++) {
            SwitchExitProbe probe = new SwitchExitProbe();
            out.append(probe.spinSwitchExit(k)).append(',');
            out.append(SwitchExitProbe.arms(k - 1)).append(',');
            out.append(SwitchExitProbe.arms(k + 1)).append(',');
        }
        out.append(SwitchExitProbe.skip(new int[] {0, 1, 2, 0, 3, 1, 0}));
        System.out.println(out);
    }
}
