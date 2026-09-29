public class CompoundTernaryProbe {
    static int calls;

    static int next() {
        calls = calls + 1;
        return calls;
    }

    static int both(int a, int b) {
        return a > 0 && b > 0 ? a : b;
    }

    static int either(int a, int b) {
        return a > 0 || b > 0 ? a + b : a - b;
    }

    static String guarded(String s, int k) {
        return s != null && k > 1 ? s : "none";
    }

    static int grouped(int a, int b, int c) {
        return (a > 0 || b > 0) && c > 0 ? 1 : 2;
    }

    static int counted(int k) {
        int v = next() % 3 == 0 || k > 2 && next() % 2 == 0 ? next() : -next();
        return v * 10 + k;
    }
}
