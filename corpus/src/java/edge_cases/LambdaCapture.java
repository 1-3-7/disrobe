import java.util.List;
import java.util.function.IntUnaryOperator;
import java.util.stream.Collectors;

public final class LambdaCapture {
    public static void main(String[] args) {
        int offset = 100;
        IntUnaryOperator adder = x -> x + offset;
        List<Integer> mapped = List.of(1, 2, 3, 4)
            .stream()
            .map(adder::applyAsInt)
            .collect(Collectors.toList());
        System.out.println(mapped);
    }
}
