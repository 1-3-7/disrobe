public class NullLocalProbe {
    static String label(int k) {
        String s = null;
        if (k > 2) {
            s = "k" + k;
        }
        return s;
    }

    static String parity(int k) {
        String t;
        if (k % 2 == 0) {
            t = "even" + k;
        } else {
            t = null;
        }
        return t;
    }
}
