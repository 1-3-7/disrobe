public class LoopHeaderDriver {
    private static int run(int mode, int value) {
        LoopHeaderProbe probe = new LoopHeaderProbe(4);
        try {
            if (mode == 0) {
                probe.spin(value == 1);
            } else if (mode == 1) {
                probe.spinElse(value == 1);
            } else {
                probe.spinSwitch(value);
            }
        } catch (IllegalStateException stop) {
            return probe.count;
        }
        return -1;
    }

    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        for (int mode = 0; mode < 3; mode++) {
            for (int value = 0; value < 3; value++) {
                out.append(run(mode, value)).append(',');
            }
        }
        System.out.println(out);
    }
}
