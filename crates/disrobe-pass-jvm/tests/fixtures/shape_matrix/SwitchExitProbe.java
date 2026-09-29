public class SwitchExitProbe {
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
                    k--;
                    break;
                default:
                    count += 11;
                    k -= 2;
                    break;
            }
            foo();
        }
    }

    public static int arms(int k) {
        int a = k;
        switch (k) {
            case 0:
                return 100;
            case 1:
                a += 7;
                break;
            case 2:
                if (a == 2) {
                    return 55;
                }
                a += 3;
            default:
                a += 11;
                break;
        }
        a = a * 2 + 1;
        return a;
    }

    public static int skip(int[] values) {
        int acc = 0;
        for (int i = 0; i < values.length; i++) {
            switch (values[i]) {
                case 0:
                    continue;
                case 1:
                    acc += 100;
                    break;
                default:
                    acc += values[i];
                    break;
            }
            acc *= 2;
        }
        return acc;
    }
}
