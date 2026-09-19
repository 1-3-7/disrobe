package fixture.initlocal;

public class InitializerLocal {
    public final int value;

    {
        class Counter {
            int next(int current) {
                return current + 1;
            }
        }
        value = new Counter().next(41);
    }

    public int value() {
        return value;
    }
}
