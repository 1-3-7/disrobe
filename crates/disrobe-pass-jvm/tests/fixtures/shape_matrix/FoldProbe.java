public class FoldProbe {
    static int sink(int a, int b) {
        return a * 1000 + b;
    }

    public static int plain(int a) {
        int n = 10;
        return sink(a, n * 2);
    }

    public static int afterIinc(int a) {
        int n = 10;
        n++;
        return sink(a, n * 2);
    }

    public static int iincInLoop(int a) {
        int n = 3;
        for (int i = 0; i < a; i++) {
            n += 2;
        }
        return sink(a, n * 2);
    }

    public static int iincOnBranch(boolean b) {
        int n = 4;
        if (b) {
            n--;
        }
        return sink(n, n + 1);
    }

    public static int iincBeforeReuse(int a) {
        int n = 7;
        int first = n * 3;
        n += a;
        return sink(first, n * 3);
    }
}
