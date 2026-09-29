public class TypeSwitchDriver {
    public static void main(String[] args) {
        Object[] values = {5, 12, "abc", null, 2.5};
        StringBuilder out = new StringBuilder();
        for (Object v : values) {
            out.append(TypeSwitchProbe.kind(v)).append(',');
        }
        System.out.println(out);
    }
}
