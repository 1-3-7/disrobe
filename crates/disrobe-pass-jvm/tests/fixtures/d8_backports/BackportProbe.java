import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class BackportProbe {
    static List<Integer> listOf0() { return List.of(); }
    static List<Integer> listOf1() { return List.of(1); }
    static List<Integer> listOf2() { return List.of(1, 2); }
    static List<Integer> listOf3() { return List.of(1, 2, 3); }
    static List<Integer> listOf4() { return List.of(1, 2, 3, 4); }
    static List<Integer> listOf5() { return List.of(1, 2, 3, 4, 5); }
    static List<Integer> listOf6() { return List.of(1, 2, 3, 4, 5, 6); }
    static List<Integer> listOf7() { return List.of(1, 2, 3, 4, 5, 6, 7); }
    static List<Integer> listOf8() { return List.of(1, 2, 3, 4, 5, 6, 7, 8); }
    static List<Integer> listOf9() { return List.of(1, 2, 3, 4, 5, 6, 7, 8, 9); }
    static List<Integer> listOf10() { return List.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10); }
    static List<Integer> listOfN() { return List.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11); }
    static List<Integer> listCopyOf(List<Integer> in) { return List.copyOf(in); }
    static Set<Integer> setOf0() { return Set.of(); }
    static Set<Integer> setOf1() { return Set.of(1); }
    static Set<Integer> setOf2() { return Set.of(1, 2); }
    static Set<Integer> setOf3() { return Set.of(1, 2, 3); }
    static Set<Integer> setOf4() { return Set.of(1, 2, 3, 4); }
    static Set<Integer> setOf5() { return Set.of(1, 2, 3, 4, 5); }
    static Set<Integer> setOfN() { return Set.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11); }
    static Set<Integer> setCopyOf(List<Integer> in) { return Set.copyOf(in); }
    static Map<String, Integer> mapOf0() { return Map.of(); }
    static Map<String, Integer> mapOf1() { return Map.of("a", 1); }
    static Map<String, Integer> mapOf2() { return Map.of("a", 1, "b", 2); }
    static Map<String, Integer> mapOf3() { return Map.of("a", 1, "b", 2, "c", 3); }
    static Map<String, Integer> mapOf4() { return Map.of("a", 1, "b", 2, "c", 3, "d", 4); }
    static Map<String, Integer> mapOf5() { return Map.of("a", 1, "b", 2, "c", 3, "d", 4, "e", 5); }
    static Map<String, Integer> mapCopyOf(Map<String, Integer> in) { return Map.copyOf(in); }
    static Map<String, Integer> mapOfEntries() { return Map.ofEntries(Map.entry("a", 1), Map.entry("b", 2)); }
    static Map.Entry<String, Integer> mapEntry() { return Map.entry("k", 9); }
    static int objectsCheckIndex(int i, int n) { return Objects.checkIndex(i, n); }
    static String objectsRequireNonNullElse(String s) { return Objects.requireNonNullElse(s, "d"); }
    static boolean objectsIsNull(Object o) { return Objects.isNull(o); }
    static boolean objectsNonNull(Object o) { return Objects.nonNull(o); }
    static int integerHashCode(int v) { return Integer.hashCode(v); }
    static int longHashCode(long v) { return Long.hashCode(v); }
    static int doubleHashCode(double v) { return Double.hashCode(v); }
    static int booleanHashCode(boolean v) { return Boolean.hashCode(v); }
    static int characterHashCode(char v) { return Character.hashCode(v); }
    static int integerSum(int a, int b) { return Integer.sum(a, b); }
    static int integerMax(int a, int b) { return Integer.max(a, b); }
    static long longSum(long a, long b) { return Long.sum(a, b); }
    static int mathFloorMod(int a, int b) { return Math.floorMod(a, b); }
    static int mathFloorDiv(int a, int b) { return Math.floorDiv(a, b); }
    static int mathToIntExact(long v) { return Math.toIntExact(v); }
    static int mathAddExact(int a, int b) { return Math.addExact(a, b); }
    static int mathMultiplyExact(int a, int b) { return Math.multiplyExact(a, b); }
    static String stringJoin(String sep, List<String> parts) { return String.join(sep, parts); }
    static String stringRepeat(String s, int n) { return s.repeat(n); }
    static boolean stringIsBlank(String s) { return s.isBlank(); }
    static String stringStrip(String s) { return s.strip(); }
    static boolean optionalIsEmpty(Optional<String> o) { return o.isEmpty(); }
    static String optionalOrElseThrow(Optional<String> o) { return o.orElseThrow(); }
    static Stream<String> optionalStream(Optional<String> o) { return o.stream(); }
    static List<String> streamToList(Stream<String> s) { return s.toList(); }
    static Comparator<String> comparatorNaturalOrder() { return Comparator.naturalOrder(); }
    static Comparator<String> comparatorComparingInt() { return Comparator.comparingInt(String::length); }
    static IntStream intStreamRange(int a, int b) { return IntStream.range(a, b); }
    static Stream<String> streamOf1(String a) { return Stream.of(a); }
    static Stream<String> streamOfN(String a, String b) { return Stream.of(a, b); }
    static Stream<Integer> streamGenerate() { return Stream.generate(() -> 7).limit(2); }
    static IntStream arraysStream(int[] v) { return Arrays.stream(v); }
    static String tryWithResources() throws Exception {
        try (ExecutorService pool = Executors.newSingleThreadExecutor()) {
            return pool.submit(() -> "ok").get();
        }
    }
    static void executorClose(ExecutorService pool) { pool.close(); }
    static String objectsToString(Object o) { return Objects.toString(o, "null"); }
    static int objectsCompare(String a, String b) { return Objects.compare(a, b, Comparator.naturalOrder()); }
    static int objectsHash(Object a, Object b) { return Objects.hash(a, b); }

    public static void main(String[] args) throws Exception {
        StringBuilder out = new StringBuilder();
        out.append(listOf0()).append(listOf1()).append(listOf2()).append(listOf3()).append(listOf4()).append(listOf5());
        out.append(listOf6()).append(listOf7()).append(listOf8()).append(listOf9()).append(listOf10()).append(listOfN());
        out.append(listCopyOf(listOf3())).append(setOf0()).append(setOf1().size()).append(setOf2().size()).append(setOf3().size());
        out.append(setOf4().size()).append(setOf5().size()).append(setOfN().size()).append(setCopyOf(listOf2()).size());
        out.append(mapOf0()).append(mapOf1()).append(mapOf2().size()).append(mapOf3().size()).append(mapOf4().size()).append(mapOf5().size());
        out.append(mapCopyOf(mapOf1())).append(mapOfEntries().size()).append(mapEntry());
        out.append(objectsCheckIndex(1, 3)).append(objectsRequireNonNullElse(null)).append(objectsIsNull(null)).append(objectsNonNull(null));
        out.append(integerHashCode(5)).append(longHashCode(6L)).append(doubleHashCode(1.5)).append(booleanHashCode(true)).append(characterHashCode('c'));
        out.append(integerSum(1, 2)).append(integerMax(3, 4)).append(longSum(5L, 6L));
        out.append(mathFloorMod(-7, 3)).append(mathFloorDiv(-7, 3)).append(mathToIntExact(8L)).append(mathAddExact(1, 1)).append(mathMultiplyExact(2, 3));
        out.append(stringJoin("-", listOf2().stream().map(String::valueOf).collect(Collectors.toList())));
        out.append(stringRepeat("ab", 2)).append(stringIsBlank(" ")).append(stringStrip(" x "));
        out.append(optionalIsEmpty(Optional.empty())).append(optionalOrElseThrow(Optional.of("v"))).append(optionalStream(Optional.of("w")).count());
        out.append(streamToList(Stream.of("p", "q"))).append(comparatorNaturalOrder().compare("a", "b")).append(comparatorComparingInt().compare("aa", "b"));
        out.append(intStreamRange(0, 3).sum()).append(streamOf1("s").count()).append(streamOfN("s", "t").count()).append(streamGenerate().count());
        out.append(arraysStream(new int[] {1, 2, 3}).sum()).append(tryWithResources());
        out.append(objectsToString(null)).append(objectsCompare("a", "a")).append(objectsHash("a", "b"));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        executorClose(pool);
        out.append(pool.isShutdown());
        System.out.println(out);
    }
}
