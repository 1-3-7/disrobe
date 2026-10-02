import java.util.List;

public final class Sink {
    private static final StringBuilder TEXT = new StringBuilder();

    private Sink() {
    }

    public static void reset() {
        TEXT.setLength(0);
    }

    public static void emit(int value) {
        TEXT.append(value).append(' ');
    }

    public static void emit(String value) {
        TEXT.append(value).append(' ');
    }

    public static void emit(List<Integer> values) {
        TEXT.append(values).append(' ');
    }

    public static int f(int x, int k) {
        return x > k ? x - k : x + k;
    }

    public static String take() {
        return TEXT.toString();
    }
}
