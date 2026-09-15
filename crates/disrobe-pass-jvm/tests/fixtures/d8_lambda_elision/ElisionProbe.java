import java.util.function.IntBinaryOperator;
import java.util.function.IntSupplier;
import java.util.function.IntUnaryOperator;
import java.util.function.LongSupplier;

public final class ElisionProbe {
    private final int seed;

    ElisionProbe(int seed) {
        this.seed = seed;
    }

    private int scale(int value) {
        return value * seed;
    }

    private static int mix(int left, int right) {
        return left * 31 + right;
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
        return (left, right) -> scale(left) + mix(offset, right);
    }

    static LongSupplier wideCapture(long base) {
        return () -> base * 7L + 4L;
    }

    static IntSupplier textCapture(String prefix) {
        return () -> prefix.length() * 5;
    }
}
