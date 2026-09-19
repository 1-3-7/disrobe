package fixture.bool;

public class BooleanBoundary {
    private boolean flag;
    private static boolean shared;
    private final boolean[] flags = new boolean[4];

    public boolean echo(boolean value) {
        return value;
    }

    public void remember(boolean value) {
        this.flag = value;
    }

    public static void share(boolean value) {
        shared = value;
    }

    public void mark(int index, boolean value) {
        flags[index] = value;
    }

    public void copy(boolean[] source, boolean[] target, int index) {
        target[index] = source[index];
    }

    public boolean current() {
        return flag;
    }

    public static boolean sharedValue() {
        return shared;
    }

    public boolean both(boolean left, boolean right) {
        return left & right;
    }

    public boolean either(boolean left, boolean right) {
        return left | right;
    }

    public boolean differ(boolean left, boolean right) {
        return left ^ right;
    }

    public boolean negate(boolean value) {
        return !value;
    }

    public void rememberBoth(boolean left, boolean right) {
        this.flag = left & right;
    }

    public void rememberNegated(boolean value) {
        this.flag = !value;
    }

    public static void shareEither(boolean left, boolean right) {
        shared = left | right;
    }

    public void markDiffer(int index, boolean left, boolean right) {
        flags[index] = left ^ right;
    }
}
