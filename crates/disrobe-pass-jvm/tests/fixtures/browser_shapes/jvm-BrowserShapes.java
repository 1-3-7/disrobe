abstract class BrowserShapes {
    static final long ABOVE_SAFE = 9007199254740993L;
    static final double RATIO = 1.25;

    abstract int absent(int value);

    native int nativeCall();

    String grade(int value) {
        return switch (value) {
            case 1 -> "A";
            case 2 -> "B";
            default -> "default";
        };
    }

    static int add(int left, int right) {
        return left + right;
    }
}
