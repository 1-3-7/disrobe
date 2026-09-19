package fixture.multidex;

public class Outer<T> {
    public static final class Inner<U extends Comparable<U>> {
        public final U value;

        public Inner(U value) {
            this.value = value;
        }

        public U get() {
            return value;
        }
    }

    public Inner<String> make() {
        return new Inner<String>("inner");
    }
}
