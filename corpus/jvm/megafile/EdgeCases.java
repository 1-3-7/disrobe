import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntBinaryOperator;
import java.util.function.IntUnaryOperator;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class EdgeCases {

    public static final int MAGIC = 0xCAFEBABE;
    public static final long BIG_PRIME = 982451653L;
    public static final double GOLDEN = 1.6180339887498949;
    public static final float TAU_F = 6.2831855f;
    public static final char ESC = '';
    public static final String EMPTY = "";
    public static final String GREETING = """
            ------------------------------
            jvm edge cases mega-fixture
            covers java 1.0 .. 25 LTS
            ------------------------------
            """;

    private static final AtomicInteger CTR = new AtomicInteger(0);
    private static final AtomicLong NANOS = new AtomicLong(System.nanoTime());
    private static final AtomicReference<String> NAME = new AtomicReference<>("anon");

    static {
        CTR.set(1);
        NAME.set("init");
    }

    {
        bumpStatic();
    }

    private static int bumpStatic() {
        return CTR.incrementAndGet();
    }

    public int instanceField = 7;
    public final int finalField;
    public volatile long volatileField = 0L;
    public transient String transientField = "skip-me";

    public EdgeCases() {
        this(0);
    }

    public EdgeCases(int seed) {
        this.finalField = seed * 17 + 3;
    }

    public sealed interface Shape permits Circle, Square, Triangle, EmptyShape {
        double area();
        default String label() {
            return "shape:" + getClass().getSimpleName().toLowerCase();
        }
    }

    public record Circle(double radius) implements Shape {
        public Circle {
            if (radius < 0) {
                throw new IllegalArgumentException("negative radius");
            }
        }

        @Override
        public double area() {
            return Math.PI * radius * radius;
        }
    }

    public record Square(double side) implements Shape {
        @Override
        public double area() {
            return side * side;
        }
    }

    public record Triangle(double base, double height) implements Shape {
        @Override
        public double area() {
            return 0.5 * base * height;
        }
    }

    public static final class EmptyShape implements Shape {
        public static final EmptyShape INSTANCE = new EmptyShape();

        private EmptyShape() {}

        @Override
        public double area() {
            return 0.0;
        }
    }

    public static String describeShape(Shape s) {
        return switch (s) {
            case Circle c when c.radius() > 100.0 -> "huge-circle:" + c.area();
            case Circle c -> "circle:" + c.area();
            case Square sq -> "square:" + sq.area();
            case Triangle t -> "tri:" + t.area();
            case EmptyShape e -> "empty";
        };
    }

    public static double totalArea(List<Shape> shapes) {
        return shapes.stream().mapToDouble(Shape::area).sum();
    }

    public enum Direction {
        NORTH(0, 1) {
            @Override
            public Direction turn() {
                return EAST;
            }
        },
        EAST(1, 0) {
            @Override
            public Direction turn() {
                return SOUTH;
            }
        },
        SOUTH(0, -1) {
            @Override
            public Direction turn() {
                return WEST;
            }
        },
        WEST(-1, 0) {
            @Override
            public Direction turn() {
                return NORTH;
            }
        };

        public final int dx;
        public final int dy;

        Direction(int dx, int dy) {
            this.dx = dx;
            this.dy = dy;
        }

        public abstract Direction turn();

        public Direction opposite() {
            return turn().turn();
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.METHOD, ElementType.TYPE})
    @Repeatable(TaggedSet.class)
    public @interface Tagged {
        String value();
        int priority() default 0;
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.METHOD, ElementType.TYPE})
    public @interface TaggedSet {
        Tagged[] value();
    }

    @Tagged(value = "alpha", priority = 1)
    @Tagged(value = "beta", priority = 2)
    public static class TaggedBox<T extends Comparable<T>> {
        private final T payload;

        public TaggedBox(T payload) {
            this.payload = payload;
        }

        public T unwrap() {
            return payload;
        }

        public int compareDeep(TaggedBox<T> other) {
            return Objects.compare(payload, other.payload, Comparator.naturalOrder());
        }
    }

    public interface Repository<K, V> {
        V get(K key);
        void put(K key, V value);

        default boolean containsKey(K key) {
            return get(key) != null;
        }

        default Optional<V> find(K key) {
            return Optional.ofNullable(get(key));
        }

        static <K, V> Repository<K, V> inMemory() {
            return new Repository<>() {
                private final Map<K, V> store = new ConcurrentHashMap<>();

                @Override
                public V get(K key) {
                    return store.get(key);
                }

                @Override
                public void put(K key, V value) {
                    store.put(key, value);
                }
            };
        }

        private static String formatKey(Object key) {
            return "k:" + Objects.toString(key, "null");
        }
    }

    public static <T extends Comparable<? super T>> List<T> sortedCopy(Collection<? extends T> in) {
        List<T> copy = new ArrayList<>(in);
        Collections.sort(copy);
        return copy;
    }

    public static <T, R> List<R> mapAll(List<T> items, Function<? super T, ? extends R> fn) {
        List<R> out = new ArrayList<>(items.size());
        for (T it : items) {
            out.add(fn.apply(it));
        }
        return out;
    }

    public static int sumWith(IntBinaryOperator op, int... xs) {
        int acc = 0;
        for (int x : xs) {
            acc = op.applyAsInt(acc, x);
        }
        return acc;
    }

    public static IntUnaryOperator multiplier(int by) {
        return x -> x * by;
    }

    public static <T> Supplier<T> memoize(Supplier<T> base) {
        return new Supplier<>() {
            private volatile T value;
            private volatile boolean ready;

            @Override
            public T get() {
                if (!ready) {
                    synchronized (this) {
                        if (!ready) {
                            value = base.get();
                            ready = true;
                        }
                    }
                }
                return value;
            }
        };
    }

    public static String pickWord(int n) {
        var word = switch (n) {
            case 0 -> "zero";
            case 1, 2, 3 -> "few";
            case 4, 5, 6, 7, 8, 9 -> "single-digit";
            case 10, 100, 1000 -> "decade";
            default -> {
                if (n < 0) {
                    yield "negative";
                }
                yield "many";
            }
        };
        return word;
    }

    public static Object classify(Object o) {
        if (o instanceof Integer i && i > 0) {
            return "positive-int:" + i;
        }
        if (o instanceof Long l) {
            return "long:" + l;
        }
        if (o instanceof String s && !s.isEmpty()) {
            return "non-empty-str:" + s.length();
        }
        if (o instanceof int[] arr) {
            return "int-array-len:" + arr.length;
        }
        if (o instanceof List<?> list && list.isEmpty()) {
            return "empty-list";
        }
        return "other";
    }

    public static String shapeFacts(Object o) {
        return switch (o) {
            case null -> "null";
            case Integer i -> "int:" + i;
            case Long l -> "long:" + l;
            case String s when s.length() < 4 -> "tiny:" + s;
            case String s -> "string:" + s;
            case int[] arr -> "iarr:" + arr.length;
            case Shape sh -> "shape:" + sh.area();
            default -> "other:" + o.getClass().getSimpleName();
        };
    }

    public static int divSafe(int n, int d) {
        try {
            return n / d;
        } catch (ArithmeticException ex) {
            return Integer.MIN_VALUE;
        } finally {
            CTR.incrementAndGet();
        }
    }

    public static String multiCatch(String s) {
        try {
            return s.substring(Integer.parseInt(s));
        } catch (NumberFormatException | IndexOutOfBoundsException ex) {
            return "bad:" + ex.getClass().getSimpleName();
        }
    }

    public static String tryWithResources() {
        try (var arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(ValueLayout.JAVA_INT, 4);
            for (int i = 0; i < 4; i++) {
                seg.setAtIndex(ValueLayout.JAVA_INT, i, i * 13);
            }
            int s = 0;
            for (int i = 0; i < 4; i++) {
                s += seg.getAtIndex(ValueLayout.JAVA_INT, i);
            }
            return "ffm-sum:" + s;
        }
    }

    public static String virtualThreadFanout(int n) throws InterruptedException, ExecutionException {
        var results = Collections.synchronizedList(new ArrayList<Integer>());
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                final int idx = i;
                futures.add(executor.submit(() -> {
                    Thread.sleep(1);
                    return idx * idx;
                }));
            }
            for (var f : futures) {
                results.add(f.get());
            }
        }
        return "vthread:" + results.stream().mapToInt(Integer::intValue).sum();
    }

    public static CompletableFuture<Integer> chain(int seed) {
        return CompletableFuture
            .supplyAsync(() -> seed)
            .thenApply(x -> x + 1)
            .thenCompose(x -> CompletableFuture.supplyAsync(() -> x * 2))
            .exceptionally(ex -> -1);
    }

    public static String textBlockDemo() {
        return """
                {
                  "name": "edge",
                  "value": %d,
                  "nested": {
                    "ok": true
                  }
                }
                """.formatted(CTR.get());
    }

    public static String rawEscapes() {
        return "tab\there\nnewline\rcr☃snowmanéaccent\\back\"quote";
    }

    public static int[] varargsBasic(int first, int... rest) {
        int[] out = new int[rest.length + 1];
        out[0] = first;
        System.arraycopy(rest, 0, out, 1, rest.length);
        return out;
    }

    @SafeVarargs
    public static <T> List<T> safeVarargs(T... items) {
        return new ArrayList<>(Arrays.asList(items));
    }

    public interface Adder {
        int add(int a, int b);
    }

    public interface Reducer<T, R> {
        R reduce(T acc, T x);
    }

    public static Adder adderFn() {
        return Integer::sum;
    }

    public static Reducer<Integer, Integer> reducerFn() {
        return (acc, x) -> acc + x;
    }

    public static Function<Integer, String> formatter() {
        return n -> "n=" + n;
    }

    public static Supplier<List<String>> listSupplier() {
        return ArrayList::new;
    }

    public static Consumer<Object> debugSink() {
        return o -> CTR.incrementAndGet();
    }

    public static int sumViaStream(int[] xs) {
        return IntStream.of(xs).sum();
    }

    public static Map<Integer, List<String>> groupByLength(List<String> in) {
        return in.stream().collect(Collectors.groupingBy(String::length));
    }

    public static SortedMap<String, Long> wordCount(String text) {
        return Stream.of(text.split("\\s+"))
            .filter(s -> !s.isEmpty())
            .collect(Collectors.groupingBy(Function.identity(), TreeMap::new, Collectors.counting()));
    }

    public static int recursiveFactorial(int n) {
        return n <= 1 ? 1 : n * recursiveFactorial(n - 1);
    }

    public static long iterativeFactorial(int n) {
        long acc = 1L;
        for (int i = 2; i <= n; i++) {
            acc *= i;
        }
        return acc;
    }

    public static int gcd(int a, int b) {
        while (b != 0) {
            int t = b;
            b = a % b;
            a = t;
        }
        return Math.abs(a);
    }

    public static int fib(int n) {
        if (n < 2) {
            return n;
        }
        int a = 0;
        int b = 1;
        for (int i = 2; i <= n; i++) {
            int t = a + b;
            a = b;
            b = t;
        }
        return b;
    }

    public static double accumulate(double[] xs) {
        double acc = 0.0;
        for (double x : xs) {
            acc += x;
        }
        return acc;
    }

    public static boolean isPalindrome(String s) {
        int i = 0;
        int j = s.length() - 1;
        while (i < j) {
            if (s.charAt(i) != s.charAt(j)) {
                return false;
            }
            i++;
            j--;
        }
        return true;
    }

    public static int countVowels(String s) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = Character.toLowerCase(s.charAt(i));
            if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
                count++;
            }
        }
        return count;
    }

    public static int[] reverseArray(int[] xs) {
        int n = xs.length;
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            out[i] = xs[n - 1 - i];
        }
        return out;
    }

    public static <T> T identity(T t) {
        return t;
    }

    public static <T extends Number> double sumAsDouble(List<T> xs) {
        double acc = 0.0;
        for (T t : xs) {
            acc += t.doubleValue();
        }
        return acc;
    }

    public static <T> Optional<T> firstMatch(Collection<T> in, Predicate<? super T> p) {
        for (T t : in) {
            if (p.test(t)) {
                return Optional.of(t);
            }
        }
        return Optional.empty();
    }

    public abstract static class AbstractWorker<T> implements Callable<T>, Runnable {
        protected final String name;

        protected AbstractWorker(String name) {
            this.name = name;
        }

        @Override
        public final void run() {
            try {
                call();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        public abstract String describe();
    }

    public static class CounterWorker extends AbstractWorker<Integer> {
        private final int from;
        private final int to;

        public CounterWorker(String name, int from, int to) {
            super(name);
            this.from = from;
            this.to = to;
        }

        @Override
        public Integer call() {
            int acc = 0;
            for (int i = from; i < to; i++) {
                acc += i;
            }
            return acc;
        }

        @Override
        public String describe() {
            return name + "[" + from + ".." + to + ")";
        }
    }

    public static int runWorker(CounterWorker w) {
        try {
            return w.call();
        } catch (Exception ex) {
            return -1;
        }
    }

    public static Runnable nestedAnon(int seed) {
        return new Runnable() {
            private int local = seed;

            @Override
            public void run() {
                local = local + 1;
                CTR.addAndGet(local);
            }
        };
    }

    public static Iterable<Integer> closureCaptureLoop(int n) {
        List<Iterable<Integer>> stages = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int captured = i;
            stages.add(() -> new Iterator<Integer>() {
                int seen = 0;

                @Override
                public boolean hasNext() {
                    return seen < captured + 1;
                }

                @Override
                public Integer next() {
                    return seen++;
                }
            });
        }
        return () -> new Iterator<Integer>() {
            final Iterator<Iterable<Integer>> outer = stages.iterator();
            Iterator<Integer> inner = Collections.emptyIterator();

            @Override
            public boolean hasNext() {
                while (!inner.hasNext() && outer.hasNext()) {
                    inner = outer.next().iterator();
                }
                return inner.hasNext();
            }

            @Override
            public Integer next() {
                return inner.next();
            }
        };
    }

    public static class Outer {
        private int outerVal = 42;

        public class Inner {
            public int sum(int x) {
                return outerVal + x;
            }
        }

        public static class StaticNested {
            public int hash;

            public StaticNested(int h) {
                this.hash = h;
            }
        }

        public Inner makeInner() {
            return new Inner();
        }
    }

    public static int callInner() {
        Outer o = new Outer();
        Outer.Inner inn = o.makeInner();
        return inn.sum(1);
    }

    public static <K extends Comparable<K>, V> SortedMap<K, V> intoSorted(Map<K, V> in) {
        return new TreeMap<>(in);
    }

    public static <T> Set<T> uniqueOrdered(Iterable<T> in) {
        Set<T> set = new LinkedHashSet<>();
        for (T t : in) {
            set.add(t);
        }
        return set;
    }

    public static <T> List<T> reverseList(List<T> in) {
        List<T> out = new ArrayList<>(in);
        Collections.reverse(out);
        return out;
    }

    public static <T> int countMatches(List<T> in, Predicate<? super T> pred) {
        int n = 0;
        for (T t : in) {
            if (pred.test(t)) {
                n++;
            }
        }
        return n;
    }

    public static <T> Map<Boolean, List<T>> partition(List<T> in, Predicate<? super T> pred) {
        return in.stream().collect(Collectors.partitioningBy(pred));
    }

    public static <T, R> R foldLeft(List<T> xs, R seed, BiFunction<R, ? super T, R> f) {
        R acc = seed;
        for (T t : xs) {
            acc = f.apply(acc, t);
        }
        return acc;
    }

    public static IntStream squares(int max) {
        return IntStream.range(0, max).map(i -> i * i);
    }

    public static String joinSquares(int n) {
        return squares(n).mapToObj(Integer::toString).collect(Collectors.joining(","));
    }

    public static <T extends Throwable> T mustNotNull(T t) {
        return Objects.requireNonNull(t);
    }

    public static String throwsCheckedAndReports() {
        try {
            throw new IOException("io");
        } catch (IOException ex) {
            return "caught:" + ex.getMessage();
        }
    }

    public static Map<String, Integer> mapBuilders() {
        return Map.of(
                "one", 1,
                "two", 2,
                "three", 3,
                "four", 4,
                "five", 5
        );
    }

    public static List<Integer> listBuilders() {
        return List.of(1, 1, 2, 3, 5, 8, 13, 21, 34, 55);
    }

    public static Set<String> setBuilders() {
        return Set.of("alpha", "beta", "gamma", "delta", "epsilon");
    }

    public static record Pair<A, B>(A first, B second) {
        public <X> Pair<X, B> mapFirst(Function<? super A, ? extends X> f) {
            return new Pair<>(f.apply(first), second);
        }

        public <Y> Pair<A, Y> mapSecond(Function<? super B, ? extends Y> g) {
            return new Pair<>(first, g.apply(second));
        }
    }

    public static String unpackPair(Pair<Integer, String> p) {
        if (p instanceof Pair(Integer i, String s)) {
            return s + "x" + i;
        }
        return "?";
    }

    public static Object deepPattern(Object o) {
        return switch (o) {
            case Pair(Integer i, String s) -> "pair:" + i + ":" + s;
            case Pair(Integer i, Integer j) -> "ii:" + (i + j);
            case Pair(String a, String b) -> "ss:" + a + b;
            case null -> "null";
            default -> "other";
        };
    }

    public static <T> T checkedCast(Object o, Class<T> c) {
        if (!c.isInstance(o)) {
            throw new ClassCastException("not " + c.getName());
        }
        return c.cast(o);
    }

    public static <E extends Enum<E>> Set<E> enumSet(Class<E> e) {
        Set<E> out = new LinkedHashSet<>();
        Collections.addAll(out, e.getEnumConstants());
        return out;
    }

    public static <T extends Throwable> void rethrow(T t) throws T {
        throw t;
    }

    public static int boxedMath(Integer a, Integer b) {
        return a + b + Math.max(a, b);
    }

    public static long bigCompute(long n) {
        long acc = 0L;
        for (long i = 1L; i <= n; i++) {
            acc += i * BIG_PRIME % 1000003L;
        }
        return acc;
    }

    public static String bitTwiddling(int x) {
        int popcount = Integer.bitCount(x);
        int leading = Integer.numberOfLeadingZeros(x);
        int trailing = Integer.numberOfTrailingZeros(x);
        int reverse = Integer.reverse(x);
        return "pop=" + popcount + " lz=" + leading + " tz=" + trailing + " rev=" + reverse;
    }

    public static String hexDump(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte by : b) {
            sb.append(String.format("%02x", by));
        }
        return sb.toString();
    }

    public static byte[] fillBytes(int n, byte v) {
        byte[] out = new byte[n];
        Arrays.fill(out, v);
        return out;
    }

    public static int[][] makeGrid(int rows, int cols) {
        int[][] grid = new int[rows][cols];
        for (int r = 0; r < rows; r++) {
            for (int c = 0; c < cols; c++) {
                grid[r][c] = r * cols + c;
            }
        }
        return grid;
    }

    public static int sumGrid(int[][] grid) {
        int s = 0;
        for (int[] row : grid) {
            for (int v : row) {
                s += v;
            }
        }
        return s;
    }

    public static <T> T executeWith(Executor ex, Supplier<T> task) throws InterruptedException, ExecutionException {
        var cf = new CompletableFuture<T>();
        ex.execute(() -> {
            try {
                cf.complete(task.get());
            } catch (Throwable t) {
                cf.completeExceptionally(t);
            }
        });
        return cf.get();
    }

    public static String stringInterpolation(String n, int v) {
        return "Hello, " + n + "! Value=" + v + " squared=" + (v * v);
    }

    public static <T> Optional<T> firstOf(Iterable<T> in) {
        Iterator<T> it = in.iterator();
        return it.hasNext() ? Optional.ofNullable(it.next()) : Optional.empty();
    }

    public static class Vector2D {
        public final double x;
        public final double y;

        public Vector2D(double x, double y) {
            this.x = x;
            this.y = y;
        }

        public Vector2D add(Vector2D o) {
            return new Vector2D(x + o.x, y + o.y);
        }

        public double dot(Vector2D o) {
            return x * o.x + y * o.y;
        }

        public double magnitude() {
            return Math.sqrt(x * x + y * y);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Vector2D v)) {
                return false;
            }
            return Double.compare(x, v.x) == 0 && Double.compare(y, v.y) == 0;
        }

        @Override
        public int hashCode() {
            return Objects.hash(x, y);
        }

        @Override
        public String toString() {
            return "<" + x + "," + y + ">";
        }
    }

    public static Vector2D centerOfMass(List<Vector2D> pts) {
        double sx = 0.0;
        double sy = 0.0;
        for (Vector2D p : pts) {
            sx += p.x;
            sy += p.y;
        }
        int n = Math.max(1, pts.size());
        return new Vector2D(sx / n, sy / n);
    }

    public static int hailstone(int n) {
        int steps = 0;
        while (n > 1) {
            n = (n & 1) == 0 ? n / 2 : 3 * n + 1;
            steps++;
        }
        return steps;
    }

    public static List<Integer> primesUpTo(int n) {
        boolean[] composite = new boolean[n + 1];
        List<Integer> out = new ArrayList<>();
        for (int i = 2; i <= n; i++) {
            if (!composite[i]) {
                out.add(i);
                for (long j = (long) i * i; j <= n; j += i) {
                    composite[(int) j] = true;
                }
            }
        }
        return out;
    }

    public static String binFormat(int x, int width) {
        String s = Integer.toBinaryString(x);
        if (s.length() >= width) {
            return s;
        }
        StringBuilder sb = new StringBuilder(width);
        for (int i = 0; i < width - s.length(); i++) {
            sb.append('0');
        }
        sb.append(s);
        return sb.toString();
    }

    public static int countDigits(long n) {
        int c = 0;
        if (n == 0L) {
            return 1;
        }
        long m = Math.abs(n);
        while (m > 0L) {
            m /= 10L;
            c++;
        }
        return c;
    }

    public static long sumDigits(long n) {
        long s = 0L;
        long m = Math.abs(n);
        while (m > 0L) {
            s += m % 10L;
            m /= 10L;
        }
        return s;
    }

    public static <T> List<List<T>> chunked(List<T> in, int size) {
        List<List<T>> out = new ArrayList<>();
        for (int i = 0; i < in.size(); i += size) {
            out.add(new ArrayList<>(in.subList(i, Math.min(i + size, in.size()))));
        }
        return out;
    }

    public static <T> List<Pair<T, T>> windowed(List<T> in) {
        List<Pair<T, T>> out = new ArrayList<>();
        for (int i = 0; i + 1 < in.size(); i++) {
            out.add(new Pair<>(in.get(i), in.get(i + 1)));
        }
        return out;
    }

    public static <T> T reduce(List<T> in, T zero, BiFunction<T, T, T> op) {
        T acc = zero;
        for (T t : in) {
            acc = op.apply(acc, t);
        }
        return acc;
    }

    public static int maxOrMin(int[] xs, boolean wantMax) {
        if (xs.length == 0) {
            throw new IllegalArgumentException("empty");
        }
        int best = xs[0];
        for (int i = 1; i < xs.length; i++) {
            if (wantMax ? xs[i] > best : xs[i] < best) {
                best = xs[i];
            }
        }
        return best;
    }

    public static double mean(double[] xs) {
        if (xs.length == 0) {
            return Double.NaN;
        }
        double s = 0.0;
        for (double x : xs) {
            s += x;
        }
        return s / xs.length;
    }

    public static double variance(double[] xs) {
        if (xs.length < 2) {
            return 0.0;
        }
        double m = mean(xs);
        double s = 0.0;
        for (double x : xs) {
            double d = x - m;
            s += d * d;
        }
        return s / (xs.length - 1);
    }

    public static int dotInt(int[] a, int[] b) {
        int n = Math.min(a.length, b.length);
        int acc = 0;
        for (int i = 0; i < n; i++) {
            acc += a[i] * b[i];
        }
        return acc;
    }

    public static int[][] matrixMul(int[][] a, int[][] b) {
        int n = a.length;
        int m = b[0].length;
        int k = b.length;
        int[][] out = new int[n][m];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                int s = 0;
                for (int t = 0; t < k; t++) {
                    s += a[i][t] * b[t][j];
                }
                out[i][j] = s;
            }
        }
        return out;
    }

    public static String join(Iterable<?> in, String sep) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Object o : in) {
            if (!first) {
                sb.append(sep);
            }
            sb.append(o);
            first = false;
        }
        return sb.toString();
    }

    public static <T> T tap(T value, Consumer<? super T> sideEffect) {
        sideEffect.accept(value);
        return value;
    }

    public static <T> ToIntFunction<T> constantInt(int k) {
        return t -> k;
    }

    public static <T> Comparator<T> stableOf(ToIntFunction<? super T> key) {
        return Comparator.comparingInt(key);
    }

    public static <T> void shuffleInPlace(List<T> in, long seed) {
        java.util.Random r = new java.util.Random(seed);
        for (int i = in.size() - 1; i > 0; i--) {
            int j = r.nextInt(i + 1);
            T tmp = in.get(i);
            in.set(i, in.get(j));
            in.set(j, tmp);
        }
    }

    public static <T> List<T> takeWhile(List<T> in, Predicate<? super T> p) {
        List<T> out = new ArrayList<>();
        for (T t : in) {
            if (!p.test(t)) {
                break;
            }
            out.add(t);
        }
        return out;
    }

    public static <T> List<T> dropWhile(List<T> in, Predicate<? super T> p) {
        int idx = 0;
        while (idx < in.size() && p.test(in.get(idx))) {
            idx++;
        }
        return new ArrayList<>(in.subList(idx, in.size()));
    }

    public static <T, K> Map<K, T> indexBy(List<T> in, Function<? super T, ? extends K> keyFn) {
        Map<K, T> out = new HashMap<>();
        for (T t : in) {
            out.put(keyFn.apply(t), t);
        }
        return out;
    }

    public static <T> Optional<T> coalesce(Optional<T> a, Optional<T> b) {
        return a.isPresent() ? a : b;
    }

    public static <T> List<T> repeat(T t, int n) {
        return Stream.generate(() -> t).limit(n).toList();
    }

    public static String collatzPath(int n) {
        StringBuilder sb = new StringBuilder();
        sb.append(n);
        while (n != 1) {
            n = (n & 1) == 0 ? n / 2 : 3 * n + 1;
            sb.append("->").append(n);
        }
        return sb.toString();
    }

    public static long countSetBitsRange(long lo, long hi) {
        long s = 0L;
        for (long i = lo; i <= hi; i++) {
            s += Long.bitCount(i);
        }
        return s;
    }

    public static String dispatchByType(Object o) {
        if (o == null) {
            return "null";
        }
        return switch (o) {
            case Integer i -> "i:" + i;
            case Long l -> "l:" + l;
            case Double d -> "d:" + d;
            case Float f -> "f:" + f;
            case Character c -> "c:" + c;
            case Boolean b -> "b:" + b;
            case String s -> "s:" + s;
            default -> "obj:" + o.getClass().getSimpleName();
        };
    }

    public static Number arithmeticPoly(Number a, Number b) {
        return switch (a) {
            case Integer i -> i.intValue() + b.intValue();
            case Long l -> l + b.longValue();
            case Double d -> d + b.doubleValue();
            case Float f -> f + b.floatValue();
            default -> a.doubleValue() + b.doubleValue();
        };
    }

    public static String safeString(Object o) {
        return Objects.toString(o, "<nil>");
    }

    public static <T> Stream<T> nonNull(Stream<T> in) {
        return in.filter(Objects::nonNull);
    }

    public static <T extends Comparable<T>> T clamp(T v, T lo, T hi) {
        if (v.compareTo(lo) < 0) {
            return lo;
        }
        if (v.compareTo(hi) > 0) {
            return hi;
        }
        return v;
    }

    public interface FluentBuilder<T> {
        FluentBuilder<T> set(String key, Object value);
        T build();
    }

    public static FluentBuilder<Map<String, Object>> mapBuilder() {
        var data = new java.util.LinkedHashMap<String, Object>();
        return new FluentBuilder<>() {
            @Override
            public FluentBuilder<Map<String, Object>> set(String key, Object value) {
                data.put(key, value);
                return this;
            }

            @Override
            public Map<String, Object> build() {
                return Map.copyOf(data);
            }
        };
    }

    public static void main(String[] args) throws Exception {
        System.out.println(GREETING);
        EdgeCases e = new EdgeCases(args.length);
        System.out.println("finalField=" + e.finalField);
        System.out.println("ctr=" + CTR.get());

        List<Shape> shapes = List.of(
                new Circle(1.0),
                new Square(2.0),
                new Triangle(3.0, 4.0),
                EmptyShape.INSTANCE
        );
        for (Shape s : shapes) {
            System.out.println(describeShape(s));
        }
        System.out.println("area=" + totalArea(shapes));

        System.out.println("dir=" + Direction.NORTH.turn().opposite());

        var box = new TaggedBox<String>("hi");
        System.out.println("box=" + box.unwrap());

        Repository<String, Integer> repo = Repository.inMemory();
        repo.put("k", 42);
        System.out.println("repo=" + repo.find("k").orElse(-1));

        System.out.println("sorted=" + sortedCopy(List.of(3, 1, 2)));
        System.out.println("mapped=" + mapAll(List.of(1, 2, 3), x -> x * 10));
        System.out.println("sum=" + sumWith(Integer::sum, 1, 2, 3, 4));
        System.out.println("mul=" + multiplier(7).applyAsInt(6));
        Supplier<String> memo = memoize(() -> "computed");
        System.out.println("memo=" + memo.get() + "/" + memo.get());

        System.out.println("word=" + pickWord(7));
        System.out.println("class=" + classify(42));
        System.out.println("class=" + classify("abc"));
        System.out.println("class=" + classify(new int[]{1, 2, 3}));
        System.out.println("class=" + classify(List.of()));
        System.out.println("facts=" + shapeFacts("hello"));

        System.out.println("div=" + divSafe(10, 0));
        System.out.println("mc=" + multiCatch("abc"));

        System.out.println(tryWithResources());
        System.out.println(virtualThreadFanout(4));
        System.out.println("cf=" + chain(10).get());

        System.out.println(textBlockDemo());
        System.out.println(rawEscapes());
        System.out.println("vararg=" + Arrays.toString(varargsBasic(1, 2, 3)));
        System.out.println("sv=" + safeVarargs("a", "b", "c"));

        System.out.println("add=" + adderFn().add(2, 3));
        System.out.println("red=" + reducerFn().reduce(10, 5));
        System.out.println("fmt=" + formatter().apply(99));
        System.out.println("ls=" + listSupplier().get());

        System.out.println("ss=" + sumViaStream(new int[]{1, 2, 3}));
        System.out.println("gb=" + groupByLength(List.of("a", "bb", "ccc", "dd")));
        System.out.println("wc=" + wordCount("a b a c b a"));

        System.out.println("fact=" + recursiveFactorial(6));
        System.out.println("ifact=" + iterativeFactorial(10));
        System.out.println("gcd=" + gcd(12, 18));
        System.out.println("fib=" + fib(20));
        System.out.println("acc=" + accumulate(new double[]{0.5, 1.5, 2.5}));

        System.out.println("pal=" + isPalindrome("racecar"));
        System.out.println("vow=" + countVowels("supercalifragilistic"));
        System.out.println("rev=" + Arrays.toString(reverseArray(new int[]{1, 2, 3, 4, 5})));

        System.out.println("id=" + identity("x"));
        System.out.println("sum=" + sumAsDouble(List.of(1, 2.5, 3L)));
        System.out.println("fm=" + firstMatch(List.of(1, 2, 3), x -> x > 1));

        CounterWorker cw = new CounterWorker("w", 0, 10);
        System.out.println("worker=" + runWorker(cw));

        Runnable anon = nestedAnon(5);
        anon.run();
        System.out.println("after-anon ctr=" + CTR.get());

        int icnt = 0;
        for (int v : closureCaptureLoop(3)) {
            icnt += v;
        }
        System.out.println("closure-sum=" + icnt);
        System.out.println("inner=" + callInner());

        SortedMap<String, Integer> sm = intoSorted(Map.of("b", 2, "a", 1));
        System.out.println("sm=" + sm);
        System.out.println("uniq=" + uniqueOrdered(List.of(1, 2, 1, 3, 2)));
        System.out.println("rev=" + reverseList(List.of(1, 2, 3)));
        System.out.println("count=" + countMatches(List.of(1, 2, 3, 4), x -> x % 2 == 0));
        System.out.println("part=" + partition(List.of(1, 2, 3, 4), x -> x > 2));
        System.out.println("fold=" + foldLeft(List.of(1, 2, 3), 0, Integer::sum));

        System.out.println("sq=" + joinSquares(5));
        System.out.println("checked=" + throwsCheckedAndReports());
        System.out.println("mb=" + mapBuilders().size());
        System.out.println("lb=" + listBuilders().size());
        System.out.println("sb=" + setBuilders().size());

        Pair<Integer, String> p = new Pair<>(7, "x");
        System.out.println("unpack=" + unpackPair(p));
        System.out.println("deep=" + deepPattern(p));

        System.out.println("cast=" + checkedCast(42, Integer.class));
        System.out.println("enum=" + enumSet(Direction.class).size());

        System.out.println("box=" + boxedMath(3, 4));
        System.out.println("big=" + bigCompute(100));
        System.out.println("bits=" + bitTwiddling(0xCAFEBABE));
        System.out.println("hex=" + hexDump(new byte[]{1, 2, 3}));
        System.out.println("grid-sum=" + sumGrid(makeGrid(3, 4)));

        var exec = Executors.newSingleThreadExecutor();
        try {
            System.out.println("exec=" + executeWith(exec, () -> 99));
        } finally {
            exec.shutdown();
        }

        System.out.println(stringInterpolation("you", 7));
        System.out.println("first=" + firstOf(List.of(1, 2, 3)));

        Vector2D v1 = new Vector2D(1, 2);
        Vector2D v2 = new Vector2D(3, 4);
        System.out.println("v=" + v1.add(v2));
        System.out.println("dot=" + v1.dot(v2));
        System.out.println("mag=" + v1.magnitude());
        System.out.println("com=" + centerOfMass(List.of(v1, v2)));

        System.out.println("hail=" + hailstone(27));
        System.out.println("primes=" + primesUpTo(30));
        System.out.println("bin=" + binFormat(42, 8));
        System.out.println("dig=" + countDigits(12345L));
        System.out.println("sumd=" + sumDigits(98765L));
        System.out.println("chunk=" + chunked(List.of(1, 2, 3, 4, 5), 2));
        System.out.println("win=" + windowed(List.of(1, 2, 3)));
        System.out.println("red=" + reduce(List.of(1, 2, 3), 0, Integer::sum));
        System.out.println("max=" + maxOrMin(new int[]{3, 1, 4, 1, 5, 9}, true));
        System.out.println("mean=" + mean(new double[]{1.0, 2.0, 3.0}));
        System.out.println("var=" + variance(new double[]{1.0, 2.0, 3.0, 4.0}));
        System.out.println("dot=" + dotInt(new int[]{1, 2, 3}, new int[]{4, 5, 6}));

        int[][] g = matrixMul(new int[][]{{1, 2}, {3, 4}}, new int[][]{{5, 6}, {7, 8}});
        System.out.println("mm00=" + g[0][0]);

        System.out.println("join=" + join(List.of(1, 2, 3), ":"));
        System.out.println("tap=" + tap(7, CTR::addAndGet));
        System.out.println("clamp=" + clamp(5, 0, 3));

        var builder = mapBuilder().set("k", 1).set("v", 2).build();
        System.out.println("mb=" + builder);

        System.out.println("collatz=" + collatzPath(7));
        System.out.println("bits-r=" + countSetBitsRange(0, 100));
        System.out.println("disp=" + dispatchByType(42));
        System.out.println("disp=" + dispatchByType("hi"));
        System.out.println("disp=" + dispatchByType(1.5));
        System.out.println("ap=" + arithmeticPoly(2, 3));
        System.out.println("ap=" + arithmeticPoly(2L, 3L));

        System.out.println("safe=" + safeString(null));
        System.out.println("nn=" + nonNull(Stream.of(1, null, 2)).count());
        System.out.println("repeat=" + repeat("z", 3));
        System.out.println("take=" + takeWhile(List.of(1, 2, 3, 4), x -> x < 3));
        System.out.println("drop=" + dropWhile(List.of(1, 2, 3, 4), x -> x < 3));
        System.out.println("idx=" + indexBy(List.of("a", "bb", "ccc"), String::length).size());
        System.out.println("coal=" + coalesce(Optional.empty(), Optional.of("b")));

        System.out.println("ctr-final=" + CTR.get());
        System.out.println("DONE");
    }
}
