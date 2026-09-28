public class SyncLoopProbe {
    private final Object lock = new Object();
    private final int limit;
    private int total;
    private int ticks;

    public SyncLoopProbe(int limit) {
        this.limit = limit;
    }

    private int held() {
        return Thread.holdsLock(lock) ? 1 : 100;
    }

    private void tick() {
        if (ticks >= limit) {
            throw new IllegalStateException("limit");
        }
    }

    public int pump(int n) {
        for (int i = 0; i < n; i++) {
            synchronized (lock) {
                total += i * held();
            }
        }
        return total;
    }

    public void spinLocked() {
        for (;;) {
            synchronized (lock) {
                ticks += held();
            }
            tick();
        }
    }

    public int ticks() {
        return ticks;
    }
}
