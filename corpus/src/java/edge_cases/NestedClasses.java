import java.util.function.Supplier;

public final class NestedClasses {
    private final int seed;

    public NestedClasses(int seed) {
        this.seed = seed;
    }

    final class Inner {
        int boosted() {
            return seed * 2;
        }
    }

    Supplier<Integer> makeLocal() {
        class Local {
            int compute() {
                return seed + 100;
            }
        }
        return () -> new Local().compute();
    }

    Supplier<Integer> makeAnonymous() {
        return new Supplier<>() {
            @Override
            public Integer get() {
                return seed * seed;
            }
        };
    }

    public static void main(String[] args) {
        NestedClasses outer = new NestedClasses(5);
        Inner inner = outer.new Inner();
        System.out.println(inner.boosted());
        System.out.println(outer.makeLocal().get());
        System.out.println(outer.makeAnonymous().get());
    }
}
