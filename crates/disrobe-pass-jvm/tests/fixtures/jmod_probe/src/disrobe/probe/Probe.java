package disrobe.probe;

public final class Probe {
    private Probe() {}

    public static String greeting(int count) {
        StringBuilder out = new StringBuilder("probe");
        for (int i = 0; i < count; i++) {
            out.append('!');
        }
        return out.toString();
    }
}
