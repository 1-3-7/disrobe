import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class GenericBound {
    static <T extends Comparable<T>> T maxOf(List<T> values) {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("empty");
        }
        T best = values.get(0);
        for (T candidate : values) {
            if (candidate.compareTo(best) > 0) {
                best = candidate;
            }
        }
        return best;
    }

    static <T> List<T> sortedCopy(List<T> source, Comparator<? super T> cmp) {
        List<T> copy = new ArrayList<>(source);
        copy.sort(cmp);
        return copy;
    }

    public static void main(String[] args) {
        List<String> names = List.of("delta", "alpha", "charlie", "bravo");
        System.out.println(maxOf(names));
        System.out.println(sortedCopy(names, Comparator.reverseOrder()));
    }
}
