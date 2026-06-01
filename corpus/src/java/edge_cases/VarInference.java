import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class VarInference {
    public static void main(String[] args) {
        var numbers = List.of(1, 2, 3, 4, 5);
        var lookup = new HashMap<String, List<Integer>>();
        var greeting = "hello";
        lookup.put("evens", numbers.stream().filter(n -> n % 2 == 0).toList());
        lookup.put("odds", numbers.stream().filter(n -> n % 2 != 0).toList());
        for (Map.Entry<String, List<Integer>> entry : lookup.entrySet()) {
            System.out.println(greeting + " " + entry.getKey() + " " + entry.getValue());
        }
    }
}
