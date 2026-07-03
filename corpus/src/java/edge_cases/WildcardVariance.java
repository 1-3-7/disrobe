import java.util.ArrayList;
import java.util.List;

public final class WildcardVariance {
    static double sumOfNumbers(List<? extends Number> source) {
        double total = 0.0;
        for (Number n : source) {
            total += n.doubleValue();
        }
        return total;
    }

    static <T> void copyAll(List<? extends T> src, List<? super T> dst) {
        for (T item : src) {
            dst.add(item);
        }
    }

    public static void main(String[] args) {
        List<Integer> ints = List.of(1, 2, 3);
        List<Number> nums = new ArrayList<>();
        copyAll(ints, nums);
        System.out.println(sumOfNumbers(ints) + " " + nums.size());
    }
}
