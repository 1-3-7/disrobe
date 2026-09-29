public class TypeSwitchProbe {
    public static String kind(Object o) {
        return switch (o) {
            case Integer i when i > 10 -> "big" + i;
            case Integer i -> "int" + i;
            case String s -> "str" + s.length();
            case null -> "null";
            default -> "other";
        };
    }
}
