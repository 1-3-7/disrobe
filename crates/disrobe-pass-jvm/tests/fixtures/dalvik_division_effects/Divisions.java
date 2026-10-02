import java.util.ArrayList;
import java.util.List;

public final class Divisions {
    private Divisions() {
    }

    public static String orderedBeforeAppend(int a, int b, int d) {
        List<Integer> t = new ArrayList<>();
        int c = 8;
        try {
            c = a / b;
            t.add(1 - d);
        } catch (ArithmeticException error) {
            t.add(99);
        }
        return t + ":" + c;
    }

    public static String unusedQuotientInTry(int b, int d) {
        String seen = "ok";
        try {
            b = b / (d - 5);
        } catch (ArithmeticException error) {
            seen = "zero";
        }
        return seen;
    }

    public static String unusedRemainderInTry(int b, int d) {
        String seen = "ok";
        try {
            b = b % (d - 3);
        } catch (ArithmeticException error) {
            seen = "zero";
        }
        return seen;
    }

    public static String unusedLongQuotientInTry(long b, long d) {
        String seen = "ok";
        try {
            b = b / (d - 2L);
        } catch (ArithmeticException error) {
            seen = "zero";
        }
        return seen;
    }

    public static String nestedUnusedQuotient(int a, int b, int d) {
        List<Integer> t = new ArrayList<>();
        int c = 8;
        try {
            c = a / b;
            t.add(1 - d);
            try {
                b = b / (d - 5);
            } catch (ArithmeticException error) {
                t.add(-1);
            }
            t.add(c);
        } catch (ArithmeticException error) {
            t.add(-2);
        }
        return t.toString();
    }
}
