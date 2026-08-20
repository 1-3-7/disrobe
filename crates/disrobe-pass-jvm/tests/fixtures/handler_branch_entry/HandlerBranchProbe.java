public final class HandlerBranchProbe {
    public static boolean check(String left, String right) {
        if (left == null) {
            return false;
        }
        if (left.equals(right)) {
            return false;
        }
        try {
            if (Integer.parseInt(left) != 2) {
                return false;
            }
            return "include".equals(right);
        } catch (NumberFormatException unused) {
            return false;
        }
    }

    public static int classify(String value, int mode) {
        if (value == null) {
            return -1;
        }
        switch (mode) {
            case 0:
                return 0;
            case 1:
                return -1;
            default:
                break;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException unused) {
            return -1;
        }
    }
}
