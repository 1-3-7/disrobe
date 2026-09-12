import java.util.function.IntUnaryOperator;

public final class CapturedLambdaProbe {
    private int base(int value) {
        return value;
    }

    private static int combine(int base, int delta, int value) {
        return delta;
    }

    IntUnaryOperator make(int delta) {
        return value -> combine(this.base(value), delta, value);
    }

    static int run(int delta, int value) {
        return new CapturedLambdaProbe().make(delta).applyAsInt(value);
    }
}
