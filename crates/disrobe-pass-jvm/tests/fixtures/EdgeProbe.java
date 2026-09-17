import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class EdgeProbe {
    interface Call {
        Object call() throws Throwable;
    }

    static AtomicInteger CTR;
    static long budgetMillis = 5000L;

    static final String[] SYNTH = {
        "chain$0", "chain$1", "chain$2", "chain$3", "chain$4",
        "closureCaptureLoop$0", "closureCaptureLoop$1",
        "constantInt$0", "debugSink$0", "executeWith$0", "formatter$0",
        "main$0", "main$1", "main$2", "main$3", "main$4", "main$5", "main$6", "main$7",
        "multiplier$0", "reducerFn$0", "repeat$0", "squares$0",
        "virtualThreadFanout$0", "wordCount$0",
    };

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            budgetMillis = Long.parseLong(args[0]);
        }
        Field ctr = EdgeCases.class.getDeclaredField("CTR");
        ctr.setAccessible(true);
        CTR = (AtomicInteger) ctr.get(null);
        members();
        for (String suffix : SYNTH) {
            final String s = suffix;
            obs("lambda$" + s, () -> invokeSynth(s));
        }
    }

    static void obs(String name, Call c) {
        CTR.set(0);
        String[] slot = {"timeout"};
        Thread worker = new Thread(() -> {
            try {
                slot[0] = render(c.call());
            } catch (Throwable t) {
                Throwable root = t;
                while (root instanceof InvocationTargetException && root.getCause() != null) {
                    root = root.getCause();
                }
                slot[0] = "throw:" + root.getClass().getName() + ":" + root.getMessage();
            }
        });
        worker.setDaemon(true);
        worker.start();
        try {
            worker.join(budgetMillis);
        } catch (InterruptedException ex) {
            slot[0] = "interrupted";
        }
        String safe = slot[0] == null ? "null-toString" : slot[0];
        if (safe.indexOf(10) >= 0 || safe.indexOf(13) >= 0) {
            safe = "codepoints:" + Arrays.toString(safe.chars().toArray());
        }
        System.out.println(name + "=" + safe + ",ctr=" + CTR.get());
        System.out.flush();
    }

    static List<Object> drain(Iterator<?> it) {
        List<Object> out = new ArrayList<>();
        int guard = 0;
        while (it.hasNext() && guard++ < 512) {
            out.add(it.next());
        }
        return out;
    }

    static boolean orderUnspecified(Object o) {
        Class<?> c = o.getClass();
        return c == HashMap.class
            || c == HashSet.class
            || c.getName().startsWith("java.util.ImmutableCollections$");
    }

    static String render(Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof int[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof long[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof double[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof byte[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof boolean[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof char[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof float[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof short[] a) {
            return Arrays.toString(a);
        }
        if (o instanceof Object[] a) {
            return Arrays.deepToString(a);
        }
        if (o instanceof IntStream s) {
            return s.boxed().collect(Collectors.toList()).toString();
        }
        if (o instanceof Stream<?> s) {
            return s.collect(Collectors.toList()).toString();
        }
        if (o instanceof CompletionStage<?> s) {
            return "cs:" + settled(s.toCompletableFuture());
        }
        if (o instanceof Future<?> f) {
            return "fut:" + settled(f);
        }
        if (o instanceof Iterator<?> it) {
            return drain(it).toString();
        }
        if (o instanceof Map<?, ?> m) {
            return orderUnspecified(m) ? sortedMap(m) : String.valueOf(m);
        }
        if (o instanceof Set<?> s) {
            return orderUnspecified(s) ? sortedSet(s) : String.valueOf(s);
        }
        if (o instanceof Iterable<?> ib && !(o instanceof Collection<?>)) {
            return drain(ib.iterator()).toString();
        }
        return String.valueOf(o);
    }

    static String settled(Future<?> f) {
        try {
            return render(f.get());
        } catch (Throwable t) {
            Throwable root = t.getCause() == null ? t : t.getCause();
            return "throw:" + root.getClass().getName() + ":" + root.getMessage();
        }
    }

    static String sortedMap(Map<?, ?> m) {
        TreeMap<String, String> t = new TreeMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            t.put(render(e.getKey()), render(e.getValue()));
        }
        return t.toString();
    }

    static String sortedSet(Set<?> s) {
        TreeSet<String> t = new TreeSet<>();
        for (Object o : s) {
            t.add(render(o));
        }
        return t.toString();
    }

    static Object canonical(Class<?> t) {
        if (t == int.class) {
            return 2;
        }
        if (t == long.class) {
            return 3L;
        }
        if (t == double.class) {
            return 1.5;
        }
        if (t == float.class) {
            return 2.5f;
        }
        if (t == boolean.class) {
            return Boolean.TRUE;
        }
        if (t == char.class) {
            return 'z';
        }
        if (t == byte.class) {
            return (byte) 7;
        }
        if (t == short.class) {
            return (short) 9;
        }
        if (t == Integer.class) {
            return 3;
        }
        if (t == Long.class) {
            return 4L;
        }
        if (t == String.class) {
            return "abc";
        }
        if (t == Throwable.class) {
            return new IllegalStateException("probe");
        }
        if (t == CompletableFuture.class) {
            return new CompletableFuture<Object>();
        }
        if (t == Supplier.class) {
            return (Supplier<Object>) () -> "supplied";
        }
        if (t == List.class) {
            return List.of(List.of(10, 20), List.of(30));
        }
        return "obj";
    }

    static Method declared(String name) {
        for (Method cand : EdgeCases.class.getDeclaredMethods()) {
            if (cand.getName().equals(name)) {
                return cand;
            }
        }
        return null;
    }

    static Object invokeSynth(String suffix) throws Throwable {
        Method found = declared("synthLambda$" + suffix);
        if (found == null) {
            found = declared("lambda$" + suffix);
        }
        if (found == null) {
            return "absent";
        }
        found.setAccessible(true);
        Class<?>[] ps = found.getParameterTypes();
        Object[] args = new Object[ps.length];
        for (int i = 0; i < ps.length; i++) {
            args[i] = canonical(ps[i]);
        }
        Object r = found.invoke(null, args);
        StringBuilder extra = new StringBuilder();
        for (Object a : args) {
            if (a instanceof CompletableFuture) {
                CompletableFuture<Object> cf = (CompletableFuture<Object>) a;
                extra.append("|arg-cf:").append(render(cf.getNow("pending")));
            }
        }
        String head = found.getReturnType() == void.class ? "void" : render(r);
        return head + extra;
    }

    static Object priv(String name, Class<?>[] types, Object[] args) throws Throwable {
        Method m = EdgeCases.class.getDeclaredMethod(name, types);
        m.setAccessible(true);
        return m.invoke(null, args);
    }

    static void members() {
        obs("bumpStatic", () -> priv("bumpStatic", new Class<?>[0], new Object[0]));
        obs("<init>#default", () -> {
            EdgeCases e = new EdgeCases();
            return e.finalField + "/" + e.instanceField + "/" + e.volatileField + "/"
                + e.transientField;
        });
        obs("<init>#seed", () -> new EdgeCases(5).finalField);

        obs("describeShape#circle", () -> EdgeCases.describeShape(new EdgeCases.Circle(2.0)));
        obs("describeShape#huge", () -> EdgeCases.describeShape(new EdgeCases.Circle(200.0)));
        obs("describeShape#square", () -> EdgeCases.describeShape(new EdgeCases.Square(3.0)));
        obs("describeShape#tri", () -> EdgeCases.describeShape(new EdgeCases.Triangle(3.0, 4.0)));
        obs("totalArea", () -> EdgeCases.totalArea(
            List.of(new EdgeCases.Circle(1.0), new EdgeCases.Square(2.0))));
        obs("sortedCopy", () -> EdgeCases.sortedCopy(List.of(3, 1, 2)));
        obs("mapAll", () -> EdgeCases.mapAll(List.of(1, 2, 3), x -> x * 10));
        obs("sumWith", () -> EdgeCases.sumWith(Integer::sum, 1, 2, 3, 4));
        obs("sumWith#empty", () -> EdgeCases.sumWith(Integer::sum));
        obs("multiplier", () -> EdgeCases.multiplier(7).applyAsInt(6));
        obs("memoize", () -> {
            int[] calls = {0};
            Supplier<String> s = EdgeCases.memoize(() -> "computed" + calls[0]++);
            return s.get() + "/" + s.get() + "/calls=" + calls[0];
        });
        obs("pickWord#0", () -> EdgeCases.pickWord(0));
        obs("pickWord#few", () -> EdgeCases.pickWord(2));
        obs("pickWord#single", () -> EdgeCases.pickWord(7));
        obs("pickWord#decade", () -> EdgeCases.pickWord(100));
        obs("pickWord#negative", () -> EdgeCases.pickWord(-4));
        obs("pickWord#many", () -> EdgeCases.pickWord(42));
        obs("classify#int", () -> EdgeCases.classify(42));
        obs("classify#negint", () -> EdgeCases.classify(-42));
        obs("classify#long", () -> EdgeCases.classify(7L));
        obs("classify#str", () -> EdgeCases.classify("abc"));
        obs("classify#emptystr", () -> EdgeCases.classify(""));
        obs("classify#arr", () -> EdgeCases.classify(new int[] {1, 2, 3}));
        obs("classify#emptylist", () -> EdgeCases.classify(List.of()));
        obs("classify#other", () -> EdgeCases.classify(1.5));
        obs("shapeFacts#null", () -> EdgeCases.shapeFacts(null));
        obs("shapeFacts#int", () -> EdgeCases.shapeFacts(42));
        obs("shapeFacts#long", () -> EdgeCases.shapeFacts(7L));
        obs("shapeFacts#tiny", () -> EdgeCases.shapeFacts("abc"));
        obs("shapeFacts#string", () -> EdgeCases.shapeFacts("hello"));
        obs("shapeFacts#iarr", () -> EdgeCases.shapeFacts(new int[] {1, 2}));
        obs("shapeFacts#other", () -> EdgeCases.shapeFacts(1.5));
        obs("divSafe#throws", () -> EdgeCases.divSafe(10, 0));
        obs("divSafe#ok", () -> EdgeCases.divSafe(10, 2));
        obs("multiCatch#nfe", () -> EdgeCases.multiCatch("abc"));
        obs("multiCatch#oob", () -> EdgeCases.multiCatch("9"));
        obs("multiCatch#ok", () -> EdgeCases.multiCatch("1"));
        obs("tryWithResources", EdgeCases::tryWithResources);
        obs("virtualThreadFanout", () -> EdgeCases.virtualThreadFanout(4));
        obs("chain", () -> EdgeCases.chain(10));
        obs("textBlockDemo", EdgeCases::textBlockDemo);
        obs("rawEscapes", EdgeCases::rawEscapes);
        obs("varargsBasic", () -> EdgeCases.varargsBasic(1, 2, 3));
        obs("varargsBasic#none", () -> EdgeCases.varargsBasic(9));
        obs("safeVarargs", () -> EdgeCases.safeVarargs("a", "b", "c"));
        obs("adderFn", () -> EdgeCases.adderFn().add(2, 3));
        obs("reducerFn", () -> EdgeCases.reducerFn().reduce(10, 5));
        obs("formatter", () -> EdgeCases.formatter().apply(99));
        obs("listSupplier", () -> {
            List<String> l = EdgeCases.listSupplier().get();
            l.add("x");
            return l;
        });
        obs("debugSink", () -> {
            Consumer<Object> c = EdgeCases.debugSink();
            c.accept("x");
            c.accept("y");
            return "accepted";
        });
        obs("sumViaStream", () -> EdgeCases.sumViaStream(new int[] {1, 2, 3}));
        obs("groupByLength", () -> EdgeCases.groupByLength(List.of("a", "bb", "ccc", "dd")));
        obs("wordCount", () -> EdgeCases.wordCount("a b a c b a"));
        obs("recursiveFactorial", () -> EdgeCases.recursiveFactorial(6));
        obs("iterativeFactorial", () -> EdgeCases.iterativeFactorial(10));
        obs("gcd", () -> EdgeCases.gcd(12, 18));
        obs("gcd#neg", () -> EdgeCases.gcd(-12, 18));
        obs("fib", () -> EdgeCases.fib(20));
        obs("fib#small", () -> EdgeCases.fib(1));
        obs("accumulate", () -> EdgeCases.accumulate(new double[] {0.5, 1.5, 2.5}));
        obs("isPalindrome#yes", () -> EdgeCases.isPalindrome("racecar"));
        obs("isPalindrome#no", () -> EdgeCases.isPalindrome("racecars"));
        obs("countVowels", () -> EdgeCases.countVowels("supercalifragilistic"));
        obs("reverseArray", () -> EdgeCases.reverseArray(new int[] {1, 2, 3, 4, 5}));
        obs("identity", () -> EdgeCases.identity("x"));
        obs("sumAsDouble", () -> EdgeCases.sumAsDouble(List.of(1, 2.5, 3L)));
        obs("firstMatch#hit", () -> EdgeCases.firstMatch(List.of(1, 2, 3), x -> x > 1));
        obs("firstMatch#miss", () -> EdgeCases.firstMatch(List.of(1, 2, 3), x -> x > 9));
        obs("runWorker", () -> EdgeCases.runWorker(new EdgeCases.CounterWorker("w", 0, 10)));
        obs("nestedAnon", () -> {
            Runnable r = EdgeCases.nestedAnon(5);
            r.run();
            r.run();
            return "ran";
        });
        obs("closureCaptureLoop", () -> EdgeCases.closureCaptureLoop(3));
        obs("callInner", EdgeCases::callInner);
        obs("intoSorted", () -> EdgeCases.intoSorted(Map.of("b", 2, "a", 1)));
        obs("uniqueOrdered", () -> EdgeCases.uniqueOrdered(List.of(3, 1, 3, 2, 1)));
        obs("reverseList", () -> EdgeCases.reverseList(List.of(1, 2, 3)));
        obs("countMatches", () -> EdgeCases.countMatches(List.of(1, 2, 3, 4), x -> x % 2 == 0));
        obs("partition", () -> EdgeCases.partition(List.of(1, 2, 3, 4), x -> x > 2));
        obs("foldLeft", () -> EdgeCases.foldLeft(List.of(1, 2, 3), 0, Integer::sum));
        obs("squares", () -> EdgeCases.squares(5));
        obs("joinSquares", () -> EdgeCases.joinSquares(5));
        obs("mustNotNull#ok",
            () -> EdgeCases.mustNotNull(new IllegalStateException("keep")).getMessage());
        obs("mustNotNull#null", () -> EdgeCases.mustNotNull((RuntimeException) null));
        obs("throwsCheckedAndReports", EdgeCases::throwsCheckedAndReports);
        obs("mapBuilders", EdgeCases::mapBuilders);
        obs("listBuilders", EdgeCases::listBuilders);
        obs("setBuilders", EdgeCases::setBuilders);
        obs("unpackPair", () -> EdgeCases.unpackPair(new EdgeCases.Pair<>(7, "x")));
        obs("deepPattern#is", () -> EdgeCases.deepPattern(new EdgeCases.Pair<>(7, "x")));
        obs("deepPattern#ii", () -> EdgeCases.deepPattern(new EdgeCases.Pair<>(7, 8)));
        obs("deepPattern#ss", () -> EdgeCases.deepPattern(new EdgeCases.Pair<>("a", "b")));
        obs("deepPattern#null", () -> EdgeCases.deepPattern(null));
        obs("deepPattern#other", () -> EdgeCases.deepPattern("plain"));
        obs("checkedCast#ok", () -> EdgeCases.checkedCast(42, Integer.class));
        obs("checkedCast#bad", () -> EdgeCases.checkedCast("x", Integer.class));
        obs("enumSet", () -> EdgeCases.enumSet(EdgeCases.Direction.class));
        obs("rethrow", () -> {
            EdgeCases.rethrow(new IllegalStateException("rethrown"));
            return "unreachable";
        });
        obs("boxedMath", () -> EdgeCases.boxedMath(3, 4));
        obs("bigCompute", () -> EdgeCases.bigCompute(100));
        obs("bitTwiddling", () -> EdgeCases.bitTwiddling(0xCAFEBABE));
        obs("bitTwiddling#zero", () -> EdgeCases.bitTwiddling(0));
        obs("hexDump", () -> EdgeCases.hexDump(new byte[] {1, 2, 3, -1}));
        obs("fillBytes", () -> EdgeCases.fillBytes(4, (byte) 7));
        obs("makeGrid", () -> Arrays.deepToString(EdgeCases.makeGrid(3, 4)));
        obs("sumGrid", () -> EdgeCases.sumGrid(EdgeCases.makeGrid(3, 4)));
        obs("executeWith", () -> EdgeCases.executeWith(Runnable::run, () -> 99));
        obs("executeWith#throws", () -> EdgeCases.executeWith(Runnable::run, () -> {
            throw new IllegalStateException("task");
        }));
        obs("stringInterpolation", () -> EdgeCases.stringInterpolation("you", 7));
        obs("firstOf#hit", () -> EdgeCases.firstOf(List.of(1, 2, 3)));
        obs("firstOf#empty", () -> EdgeCases.firstOf(List.of()));
        obs("centerOfMass", () -> EdgeCases.centerOfMass(
            List.of(new EdgeCases.Vector2D(1, 2), new EdgeCases.Vector2D(3, 4))));
        obs("hailstone", () -> EdgeCases.hailstone(27));
        obs("primesUpTo", () -> EdgeCases.primesUpTo(30));
        obs("binFormat", () -> EdgeCases.binFormat(42, 8));
        obs("binFormat#wide", () -> EdgeCases.binFormat(1023, 4));
        obs("countDigits", () -> EdgeCases.countDigits(12345L));
        obs("countDigits#zero", () -> EdgeCases.countDigits(0L));
        obs("sumDigits", () -> EdgeCases.sumDigits(98765L));
        obs("chunked", () -> EdgeCases.chunked(List.of(1, 2, 3, 4, 5), 2));
        obs("windowed", () -> EdgeCases.windowed(List.of(1, 2, 3)));
        obs("reduce", () -> EdgeCases.reduce(List.of(1, 2, 3), 0, Integer::sum));
        obs("maxOrMin#max", () -> EdgeCases.maxOrMin(new int[] {3, 1, 4, 1, 5, 9}, true));
        obs("maxOrMin#min", () -> EdgeCases.maxOrMin(new int[] {3, 1, 4, 1, 5, 9}, false));
        obs("maxOrMin#empty", () -> EdgeCases.maxOrMin(new int[0], true));
        obs("mean", () -> EdgeCases.mean(new double[] {1.0, 2.0, 3.0}));
        obs("mean#empty", () -> EdgeCases.mean(new double[0]));
        obs("variance", () -> EdgeCases.variance(new double[] {1.0, 2.0, 3.0, 4.0}));
        obs("variance#short", () -> EdgeCases.variance(new double[] {1.0}));
        obs("dotInt", () -> EdgeCases.dotInt(new int[] {1, 2, 3}, new int[] {4, 5, 6}));
        obs("matrixMul", () -> Arrays.deepToString(
            EdgeCases.matrixMul(new int[][] {{1, 2}, {3, 4}}, new int[][] {{5, 6}, {7, 8}})));
        obs("join", () -> EdgeCases.join(List.of(1, 2, 3), ":"));
        obs("join#empty", () -> EdgeCases.join(List.of(), ":"));
        obs("tap", () -> {
            int[] hit = {0};
            Object v = EdgeCases.tap(7, o -> hit[0]++);
            return v + "/hit=" + hit[0];
        });
        obs("constantInt", () -> {
            ToIntFunction<String> f = EdgeCases.constantInt(5);
            return f.applyAsInt("anything");
        });
        obs("stableOf", () -> {
            Comparator<String> c = EdgeCases.stableOf(String::length);
            return Integer.signum(c.compare("a", "bbb")) + "/"
                + Integer.signum(c.compare("bbb", "a"));
        });
        obs("shuffleInPlace", () -> {
            List<Integer> l = new ArrayList<>(List.of(1, 2, 3, 4, 5, 6, 7, 8));
            EdgeCases.shuffleInPlace(l, 42L);
            return l;
        });
        obs("takeWhile", () -> EdgeCases.takeWhile(List.of(1, 2, 3, 4), x -> x < 3));
        obs("dropWhile", () -> EdgeCases.dropWhile(List.of(1, 2, 3, 4), x -> x < 3));
        obs("indexBy", () -> EdgeCases.indexBy(List.of("a", "bb", "ccc"), String::length));
        obs("coalesce#b", () -> EdgeCases.coalesce(Optional.empty(), Optional.of("b")));
        obs("coalesce#a", () -> EdgeCases.coalesce(Optional.of("a"), Optional.of("b")));
        obs("repeat", () -> EdgeCases.repeat("z", 3));
        obs("collatzPath", () -> EdgeCases.collatzPath(7));
        obs("countSetBitsRange", () -> EdgeCases.countSetBitsRange(0, 100));
        obs("dispatchByType#null", () -> EdgeCases.dispatchByType(null));
        obs("dispatchByType#int", () -> EdgeCases.dispatchByType(42));
        obs("dispatchByType#long", () -> EdgeCases.dispatchByType(7L));
        obs("dispatchByType#double", () -> EdgeCases.dispatchByType(1.5));
        obs("dispatchByType#float", () -> EdgeCases.dispatchByType(2.5f));
        obs("dispatchByType#char", () -> EdgeCases.dispatchByType('q'));
        obs("dispatchByType#bool", () -> EdgeCases.dispatchByType(true));
        obs("dispatchByType#str", () -> EdgeCases.dispatchByType("hi"));
        obs("dispatchByType#obj", () -> EdgeCases.dispatchByType(List.of()));
        obs("arithmeticPoly#int", () -> EdgeCases.arithmeticPoly(2, 3));
        obs("arithmeticPoly#long", () -> EdgeCases.arithmeticPoly(2L, 3L));
        obs("arithmeticPoly#double", () -> EdgeCases.arithmeticPoly(2.5, 3.5));
        obs("arithmeticPoly#float", () -> EdgeCases.arithmeticPoly(2.5f, 3.5f));
        obs("arithmeticPoly#other", () -> EdgeCases.arithmeticPoly((short) 2, (short) 3));
        obs("safeString#null", () -> EdgeCases.safeString(null));
        obs("safeString#value", () -> EdgeCases.safeString(42));
        obs("nonNull", () -> EdgeCases.nonNull(Stream.of(1, null, 2)).count());
        obs("clamp#hi", () -> EdgeCases.clamp(5, 0, 3));
        obs("clamp#lo", () -> EdgeCases.clamp(-5, 0, 3));
        obs("clamp#mid", () -> EdgeCases.clamp(2, 0, 3));
        obs("mapBuilder", () -> EdgeCases.mapBuilder().set("k", 1).set("v", 2).build());
    }
}
