public class TypeSwitchBlockDriver {
    public static void main(String[] args) {
        Object[] inputs = {5, 12, "abc", null, 2.5, 40};
        StringBuilder out = new StringBuilder();
        for (Object input : inputs) {
            out.append(TypeSwitchBlockProbe.describe(input)).append(',');
        }
        out.append(TypeSwitchBlockProbe.total);
        System.out.println(out);
    }
}
