package fixtures.constructor;

public final class ConstructorDelegateProbe {
    public final int left;
    public final int right;

    public ConstructorDelegateProbe(InputPair arg0) {
        this(arg0.left, arg0.right);
    }

    public ConstructorDelegateProbe(int left, int right) {
        this.left = left;
        this.right = right;
    }

    public static ConstructorDelegateProbe create(InputPair arg0) {
        return new ConstructorDelegateProbe(arg0);
    }

    public int score() {
        return this.left * 31 + this.right;
    }
}

final class InputPair {
    final int left;
    final int right;

    InputPair(int left, int right) {
        this.left = left;
        this.right = right;
    }
}
