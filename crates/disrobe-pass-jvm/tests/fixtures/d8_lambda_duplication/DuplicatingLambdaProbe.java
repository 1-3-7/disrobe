import java.util.function.IntUnaryOperator;

public final class DuplicatingLambdaProbe {
    private static int counter;

    private static int step(int seed, int value) {
        counter += 1;
        return seed * 31 + value + counter;
    }

    static IntUnaryOperator duplicating(int seed) {
        return value -> {
            int once = step(seed, value);
            return once + once;
        };
    }

    static IntUnaryOperator single(int seed) {
        return value -> step(seed, value) + 1;
    }

    static String run(int seed, int value) {
        counter = 0;
        int duplicated = duplicating(seed).applyAsInt(value);
        counter = 0;
        int plain = single(seed).applyAsInt(value);
        return duplicated + ":" + plain;
    }

    public static void main(String[] args) {
        System.out.println(run(3, 5));
        System.out.println(run(-2, 7));
    }
}
