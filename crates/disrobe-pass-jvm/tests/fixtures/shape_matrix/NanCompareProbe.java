public class NanCompareProbe {
    public static String doubles(double a, double b) {
        StringBuilder sb = new StringBuilder();
        sb.append(a < b ? 'T' : 'F');
        sb.append(a <= b ? 'T' : 'F');
        sb.append(a > b ? 'T' : 'F');
        sb.append(a >= b ? 'T' : 'F');
        sb.append(a == b ? 'T' : 'F');
        sb.append(a != b ? 'T' : 'F');
        if (!(a < b)) {
            sb.append('!');
        }
        if (!(a >= b)) {
            sb.append('?');
        }
        return sb.toString();
    }

    public static String floats(float a, float b) {
        StringBuilder sb = new StringBuilder();
        sb.append(a < b ? 'T' : 'F');
        sb.append(a <= b ? 'T' : 'F');
        sb.append(a > b ? 'T' : 'F');
        sb.append(a >= b ? 'T' : 'F');
        if (!(a > b)) {
            sb.append('!');
        }
        if (!(a <= b)) {
            sb.append('?');
        }
        return sb.toString();
    }

    public static boolean below(double a, double b) {
        return a < b;
    }

    public static boolean notAtLeast(float a, float b) {
        return !(a >= b);
    }

    public static int halvings(double x) {
        int n = 0;
        while (!(x < 1.0) && n < 5) {
            x /= 2;
            n++;
        }
        return n;
    }
}
