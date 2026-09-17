public class ExprCases {
    static int nestedTernaryThen(int a, int b, int c, int d, int e) {
        return a > 0 ? (b > 0 ? c : d) : e;
    }

    static int nestedTernaryElse(int a, int b, int c, int d, int e) {
        return a > 0 ? e : (b > 0 ? c : d);
    }

    static int nestedTernaryBoth(int a, int b, int c, int d, int e, int f, int g) {
        return a > 0 ? (b > 0 ? c : d) : (e > 0 ? f : g);
    }

    static String ternaryChain(int x) {
        return x > 100 ? "huge" : x > 10 ? "big" : x > 0 ? "small" : "neg";
    }

    static int ternaryAsArg(int a, int b) {
        return Math.max(a > b ? a - b : b - a, 0);
    }

    static long ternaryLong(long v, long w) {
        return v > w ? v : (w > 0L ? w : v);
    }

    static int switchExprArrow(int day) {
        return switch (day) {
            case 1, 7 -> 0;
            case 2, 3, 4, 5, 6 -> 8;
            default -> -1;
        };
    }

    static int switchExprArrowYieldBlock(int day) {
        return switch (day) {
            case 1, 7 -> 0;
            case 2, 3, 4, 5, 6 -> {
                int h = day * 8;
                yield h;
            }
            default -> {
                yield -1;
            }
        };
    }

    static int switchExprColonYield(int k) {
        int r = switch (k) {
            case 0:
                yield 100;
            case 1:
                yield 200;
            default:
                yield -1;
        };
        return r + 1;
    }

    static String switchExprStringYield(int sel) {
        return switch (sel) {
            case 0 -> "zero";
            case 1 -> {
                String s = "on";
                yield s + "e";
            }
            default -> "many";
        };
    }
}
