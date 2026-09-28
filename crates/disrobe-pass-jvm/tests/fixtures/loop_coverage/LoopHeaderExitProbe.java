public class LoopHeaderExitProbe {
    private int calls;
    public int count;

    private void foo() {
        calls++;
    }

    public int spinSwitchExit(int k) {
        for (;;) {
            switch (k) {
                case 0:
                    return count;
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
}
