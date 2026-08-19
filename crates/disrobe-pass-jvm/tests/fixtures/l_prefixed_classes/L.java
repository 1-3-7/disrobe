public final class L {
    private final int value;

    L(int value) {
        this.value = value;
    }

    int value() {
        return this.value;
    }

    static LL wrap(L left) {
        return new LL(left);
    }

    static int run(int seed) {
        return wrap(new L(seed)).total();
    }

    public static void main(String[] args) {
        System.out.println(run(7));
        System.out.println(run(-3));
    }
}

final class LL {
    private final L inner;

    LL(L inner) {
        this.inner = inner;
    }

    int total() {
        return this.inner.value() * 2;
    }
}
