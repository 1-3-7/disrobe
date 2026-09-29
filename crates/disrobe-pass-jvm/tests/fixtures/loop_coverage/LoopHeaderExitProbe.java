public class LoopHeaderExitProbe {
    private int calls;
    public int count;

    private void foo() {
        calls++;
    }

    public int spinSwitchExit(int k, boolean run) {
        if (run) {
            loop:
            for (;;) {
                switch (k) {
                    case 0:
                        break loop;
                    case 1:
                        count += 7;
                        break;
                    default:
                        count += 11;
                        break;
                }
                foo();
            }
        }
        return count * 2 + calls;
    }
}
