public class SyncLoopDriver {
    public static void main(String[] args) {
        SyncLoopProbe probe = new SyncLoopProbe(3);
        StringBuilder out = new StringBuilder();
        out.append(probe.pump(5)).append(',');
        try {
            probe.spinLocked();
        } catch (IllegalStateException stop) {
            out.append(probe.ticks());
        }
        System.out.println(out);
    }
}
