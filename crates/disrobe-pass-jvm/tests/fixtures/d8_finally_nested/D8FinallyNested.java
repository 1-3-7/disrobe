public final class D8FinallyNested {
    static int counter;

    static int run(int left, int right) {
        try {
            return left / right;
        } finally {
            try {
                counter += left / right;
            } catch (ArithmeticException ignored) {
                counter = -1;
            }
        }
    }
}
