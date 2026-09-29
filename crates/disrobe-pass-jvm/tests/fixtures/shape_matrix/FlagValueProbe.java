public class FlagValueProbe {
    static boolean seen;

    static int flagSum(int a) {
        int x = a > 3 ? 1 : 0;
        return x + 10;
    }

    static int flagSwitch(int a) {
        int s = a > 3 ? 1 : 0;
        switch (s) {
            case 0:
                return 5;
            case 1:
                return 9;
            default:
                return -1;
        }
    }

    static int dispatch(int[] box) {
        int state = 0;
        for (;;) {
            switch (state) {
                case 0:
                    box[0]++;
                    state = box[0] > 4 ? 1 : 0;
                    break;
                case 1:
                    box[0] *= 10;
                    return box[0];
            }
        }
    }

    static boolean nested(int a, int b) {
        boolean z = a > b ? b > 0 : a > 0;
        return z;
    }

    static void nestedField(int a, int b) {
        seen = a > b ? b > 0 : a < -2;
    }

    static int flags(int a) {
        return (a > 1 ? 1 : 0) + (a > 5 ? 1 : 0);
    }

    static int arguments(int a, int b) {
        return Math.max(a > b ? a : b, b > 3 ? (a > 1 ? 7 : 8) : 9);
    }
}
