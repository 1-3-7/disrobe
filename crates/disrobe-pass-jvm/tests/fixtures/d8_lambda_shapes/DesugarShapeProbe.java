import java.util.function.IntBinaryOperator;
import java.util.function.IntFunction;
import java.util.function.IntUnaryOperator;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

public final class DesugarShapeProbe {
    interface TriInt {
        int apply(int a, int b, int c);
    }

    private final int seed;

    DesugarShapeProbe(int seed) {
        this.seed = seed;
    }

    private int scale(int value) {
        return value * this.seed;
    }

    private static int mix(int a, int b) {
        return a * 31 + b;
    }

    static IntUnaryOperator stateless() {
        return value -> value * 3 + 1;
    }

    static IntUnaryOperator oneCapture(int offset) {
        return value -> mix(offset, value) + 2;
    }

    IntUnaryOperator receiverCapture() {
        return value -> scale(value) + 3;
    }

    IntBinaryOperator twoCaptures(int offset) {
        return (a, b) -> scale(a) + mix(offset, b);
    }

    static LongSupplier wideCapture(long base) {
        return () -> base * 7L + 4L;
    }

    static TriInt custom(int k) {
        return (a, b, c) -> a + b + c + k;
    }

    static IntFunction<IntUnaryOperator> nested(int k) {
        return outer -> inner -> outer * 100 + inner + k;
    }

    static Supplier<String> textCapture(String prefix) {
        return () -> prefix + "!";
    }

    static String run(int seed, int offset, long base, String prefix) {
        DesugarShapeProbe probe = new DesugarShapeProbe(seed);
        StringBuilder out = new StringBuilder();
        out.append(stateless().applyAsInt(offset));
        out.append(':');
        out.append(oneCapture(offset).applyAsInt(seed));
        out.append(':');
        out.append(probe.receiverCapture().applyAsInt(offset));
        out.append(':');
        out.append(probe.twoCaptures(offset).applyAsInt(seed, offset));
        out.append(':');
        out.append(wideCapture(base).getAsLong());
        out.append(':');
        out.append(custom(seed).apply(offset, seed, offset));
        out.append(':');
        out.append(nested(seed).apply(offset).applyAsInt(seed));
        out.append(':');
        out.append(textCapture(prefix).get());
        return out.toString();
    }

    public static void main(String[] args) {
        System.out.println(run(3, 5, 11L, "a"));
        System.out.println(run(-2, 7, -13L, "b"));
    }
}
