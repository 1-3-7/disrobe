public class LoopHeaderProbe {
    private final int limit;
    private int calls;
    public int count;

    public LoopHeaderProbe(int limit) {
        this.limit = limit;
    }

    private void foo() {
        calls++;
        if (calls >= limit) {
            throw new IllegalStateException("limit");
        }
    }

    public void spin(boolean x) {
        for (;;) {
            if (x) count++;
            foo();
        }
    }

    public void spinElse(boolean x) {
        for (;;) {
            if (x) {
                count += 2;
            } else {
                count += 3;
            }
            foo();
        }
    }

    public void spinSwitch(int k) {
        for (;;) {
            switch (k) {
                case 0:
                    count += 5;
                    break;
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
